"""Policy runner."""

import re
from datetime import datetime
from collections import namedtuple, defaultdict

from .base import _MNAccountAPIClientBase

from .policyeval import _policy_predicate_eval


_re_policy = re.compile(r'(\S+)\s+(.+?)\s*(\baccept|\breject|\bnull)?\s*;', re.DOTALL)

_final = ('accept', 'reject', 'null')

_request_selected_attributes = ('method', 'path', 'args', 'values', 'json')
Request = namedtuple('Request', _request_selected_attributes)
_request_selected_attributes_no_json = ('method', 'path', 'args', 'values')
RequestNoJson = namedtuple('Request', _request_selected_attributes_no_json)

_user_selected_attributes = ('id', 'login', 'email', 'is_active', 'is_anonymous')
User = namedtuple('User', _user_selected_attributes)

_session_selected_attributes = ('permanent', 'new', 'modified', 'accessed')
_session_selected_keys = (('_id', 'id'), ('_user_id', 'user_id'), ('uinfo', 'uinfo'))
Session = namedtuple('Session', _session_selected_attributes + tuple(i[1] for i in _session_selected_keys))


class _mnaclient(_MNAccountAPIClientBase):
    def account_post(self, params, data):
        return self._auth_call('post', '/account', params, data)

    def account_get(self, params):
        return self._auth_call('get', '/account', params)

    def policy_get(self, label):
        return self._api_call('get', '/v1/policy', {
            'policy.label': label
        })['data']


class _policy_runner:
    __slots__ = (
        '_pred_cache',
        '_pred_cache_ts',
        '_locals',
        '_mnacl',
    )


    def __init__(self, auth_url, creds):
        self._pred_cache = {}
        self._pred_cache_ts = datetime.utcnow()
        self._locals = None
        self._mnacl = _mnaclient(
            auth_url, creds
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._locals = None
        return False

    def load(self, label_, tag_):
        if label_ not in self._pred_cache:
            d = defaultdict(list)

            policy = self._mnacl.policy_get(label=label_)

            assert len(policy) is not None, 'no such policy: {}'.format(label_)

            items = policy_parse(policy[0]['statement'])

            for i in items:
                d[i[0]].append(i)

            ts = datetime.strptime(policy[0]['ts'], '%Y-%m-%dT%H:%M:%S')
            if ts > self._pred_cache_ts:
                self._pred_cache = {}
                self._pred_cache_ts = ts

            self._pred_cache[label_] = d

        statements = self._pred_cache[label_].get(tag_)

        assert statements is not None, \
                'no such tag in policy {}: {}'.format(label_, tag_)

        return statements

_pr = None



def policy_parse(s):  # noqa
    """Parse policy into list of (tag, predicate, action) tuples.

    :Pamareters:
        - s: str, policy statements

    :Return:
        list of (tag, predicate, action) tuples.
    """
    items = _re_policy.findall(s)
    return items


def _make_locals(session_, user_, req_):
    a = [getattr(session_, i) for i in _session_selected_attributes]
    k = [session_.get(i[0]) for i in _session_selected_keys]
    session = Session(*(a + k))

    user = User(*(getattr(user_, i) for i in _user_selected_attributes))

    if req_.content_type == 'application/json' and req_.content_length:
        req = Request(
            *(getattr(req_, i) for i in _request_selected_attributes))
    else:
        req = RequestNoJson(
            *(getattr(req_, i) for i in _request_selected_attributes_no_json))

    return {'session': session, 'user': user, 'req': req, 'policy': _pr}


def _policy_action(session_, user_, req_, locals_, statements, tag_selector):
    for idx, (tag, pred, action) in statements:
        tag_ = tag.strip()

        if tag_selector is not None and tag_ not in tag_selector:
            continue

        tag, res = _policy_predicate_eval(locals_, tag_, pred.strip())

        if type(res) is list:
            statements_ = [
                (idx, (tag, tpa[1], tpa[2])) for i, tpa in enumerate(res)]

            ita = _policy_action(
                session_, user_, req_, locals_, statements_, tag_selector)
            if ita[0] == -1:
                continue

            else:
                return ita
        else:
            if res:
                return idx, tag, action
            else:
                continue

    return -1, None, None


def policy_action(session_, user_, req_, policy, tag_selector=None):
    """Evaluate policy statements and return final action.

    :Parameters:
        - session_: authenticated flask session (flask.session), part of
          server context;

        - user_: authenticated user, instance of
          flask_login.mixins.UserMixin, part of server context;

        - req_: flask request under evaluation, part of server context;

        - policy: str, policy statement linked to the above user and this
          target;

        - tag_selector: optional tags to stop at, ignoring others.  If not
          given, all statements are evaluated.

    :Return:
        tuple of (index, tag, action) of the matched policy statement.

        Index is the zero-based index in the policy, tag is the
        statement's tag, and action is statement's action, one of
        "accept", "reject".

        If no policy matched, the (-1, None, None) is returned, and the
        caller can take their own decision.  Usually equivalent to
        "reject".

    :Exceptions:
        - see policyeval._policy_eval() docstring
    """
    locals_ = _make_locals(session_, user_, req_)

    items = policy_parse(policy)

    with _pr:
        _pr._locals = locals_
        return _policy_action(
            session_, user_, req_, locals_, enumerate(items), tag_selector)


def _policy_validation(
        level,
        rv,
        session_,
        user_,
        req_,
        locals_,
        statements,
        tag_selector):
    for idx, (tag, pred, action) in statements:
        tag_ = tag.strip()

        if tag_selector is not None and tag_ not in tag_selector:
            rv.append((level, idx, (tag, pred, action), 'tag-selector-skip'))
            continue

        try:
            tag, res = _policy_predicate_eval(locals_, tag_, pred.strip())

            if type(res) is list:
                statements_ = [
                    (idx, (tag, tpa[1], tpa[2])) for i, tpa in enumerate(res)]
                _policy_validation(
                    level + 1,
                    rv,
                    session_,
                    user_,
                    req_,
                    locals_,
                    statements_,
                    tag_selector)
            else:
                rv.append((level, idx, (tag, pred, action), res))

        except Exception as e:
            res = False
            rv.append((level, idx, (tag, pred, action), e))

        if type(res) is bool and res:
            return

    rv.append((level, -1, (None, None, None), None))


def policy_validation(session_, user_, req_, policy, tag_selector=None):  # noqa
    rv = []

    locals_ = _make_locals(session_, user_, req_)

    items = policy_parse(policy)

    with _pr:
        _pr._locals = locals_
        _policy_validation(
            0, rv, session_, user_, req_, locals_, enumerate(items), tag_selector)

    return rv


def get_policy_service():
    global _pr
    return _pr


def init(auth_url, creds):
    global _pr
    _pr = _policy_runner(auth_url, creds)
