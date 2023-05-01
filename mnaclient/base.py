import os
import pickle
import json
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3 import Retry

from requests.auth import AuthBase

def _requests_retry_session(
        retries=30,
        backoff_factor=0.3,
        allowed_methods=False,
        status_forcelist=(
            500,
            502,
            504,
        )):
    session = requests.Session()

    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        allowed_methods=allowed_methods,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )

    adapter = HTTPAdapter(max_retries=retry)

    session.mount('https://', adapter)

    return session


class MNAccountClient:
    """"""
    def __init__(self, base_url):
        self._session = requests.Session()
        self._base_url = base_url

    def _api_call(self, method, endpoint, params=None, data=None):
        headers = {
            'Accept': 'application/json',
        }

        if data is not None:
            headers['Content-Type'] = 'application/json'

        url = '{}{}'.format(self._base_url, endpoint)

        response = self._session.request(
            method,
            url,
            params=params,
            headers=headers,
            json=data)

        if response.status_code == 200:
            data = response.json()
            return data['data']

        elif response.status_code == 304:
            return None

        else:
            data = response.json()
            raise Exception('api failure: code {} data {}'.format(
                response.status_code, data))

    def account_get(self, ticket, login, target):
        params = {
            'ticket': ticket,
            'login': login,
            'target': target,
        }

        return self._api_call('get', '/account', params=params)

    def account_post(self, login, password, target):
        data = {
            'login': login,
            'password': password,
            'target': target,
        }

        return self._api_call('post', '/account', data=data)

    def account_delete(self, ticket):
        data = {
            'ticket': ticket,
        }

        return self._api_call('delete', '/account', data=data)


class _MNAccountAPIClientBase:
    """"""
    _session_cookie_file = '.mnaccountapiclient.cookie'

    def __init__(self, auth_url, creds, session_params=None):
        if session_params is None:
            sessopm_params = {}

        self._session = _requests_retry_session(**session_params)

        if os.path.exists(self._session_cookie_file):
            with open(self._session_cookie_file, 'rb') as f:
                saved_cookie = pickle.load(f)
                self._session.cookies.update(saved_cookie)

        self._auth_url = auth_url
        self._creds = creds
        self._login()
        self._discover_api_url()

    def _call(self, url, method, endpoint, params=None, data=None, retry_on_error=True):
        headers = {
            'Accept': 'application/json',
        }

        if data is not None:
            headers['Content-Type'] = 'application/json'

        response = self._session.request(
            method,
            '{}{}'.format(url, endpoint),
            params=params,
            headers=headers,
            json=data,
            cookies=self._session.cookies)

        with open(self._session_cookie_file, 'wb') as f:
            pickle.dump(self._session.cookies, f)

        if response.status_code == 200:
            return response.json()

        elif response.status_code == 304:
            return None

        elif response.status_code in (401, ) or response.status_code >= 500:
            if retry_on_error:
                self._login(force=True)
                return self._call(
                    url, method, endpoint, params, data, retry_on_error=False)
            else:
                res = response.json()
                raise Exception('api failure: code {} data {}'.format(
                    response.status_code, res))

        else:
            res = response.json()
            raise Exception('api failure: code {} data {}'.format(
                response.status_code, res))

    def _auth_call(self, method, endpoint, params=None, data=None, retry_on_error=True):
        return self._call(self._auth_url, method, endpoint, params, data, retry_on_error)

    def _api_call(self, method, endpoint, params=None, data=None, retry_on_error=True):
        return self._call(self._api_url, method, endpoint, params, data, retry_on_error)

    def _login(self, force=False):
        if ('session' in self._session.cookies) and not force:
            return

        if len(self._creds) == 3:
            data = {
                'login': self._creds[0],
                'password': self._creds[1],
                'target': self._creds[2],
            }
        elif len(self._creds) == 2:
            data = {
                'apikey': self._creds[0],
                'target': self._creds[1],
            }
        else:
            data = None

        data = self._auth_call('post', '/account', data=data, retry_on_error=(not force))
        # print(data)

    def _uinfo(self):
        return self._auth_call('get', '/account')

    def _discover_api_url(self):
        self._api_url = 'https://{}'.format(self._session.cookies.list_domains()[0])

        # tmpurl = urlsplit(self._auth_url)
        # self._api_url = '{}://{}'.format(tmpurl.scheme, tmpurl.netloc)

        # if len(self._creds) == 3:
        #     data = self.api_user_get(login=self._creds[0])
        #     target = self._creds[2]

        # elif len(self._creds) == 2:
        #     data = self.api_user_get(apikey=self._creds[0])
        #     target = self._creds[1]

        # else:
        #     raise Exception('invalid creds {}'.format(self._creds))

        # user = data[0]
        # data = self.api_user_target_get(user_id=user['id'])
        # t = [i for i in data if i['label'] == target]

        # url = urlsplit(t[0]['url'])
        # self._api_url = '{}://{}'.format(url.scheme, url.netloc)

    def api_version(self):
        res = self._api_call('get', '/v1/version')
        return res['data']

    # def api_init(self):
    #     res = self._api_call('put', '/v1/init')
    #     return res['data']

    # def api_refresh(self):
    #     res = self._api_call('put', '/v1/refresh')
    #     return res['data']

    # user
    def api_user_get(self, user_id=None, login=None, apikey=None):
        if user_id is not None:
            res = self._api_call('get', '/v1/user/{}'.format(user_id))

        else:
            params = {}
            if login is not None:
                params['user.login'] = login

            elif apikey is not None:
                params['user.apikey'] = apikey

            res = self._api_call('get', '/v1/user', params)

        return res['data']

    def api_user_post(self, data):
        res = self._api_call('post', '/v1/user', data=data)
        return res['data']

    def api_user_put(self, data):
        res = self._api_call('put', '/v1/user/{}'.format(data['id']), data=data)
        return res['data']

    def api_user_delete(self, user_id):
        res = self._api_call('delete', '/v1/user/{}'.format(user_id))
        return res['data']

    # target
    def api_target_get(self, target_id=None):
        if target_id is not None:
            res = self._api_call('get', '/v1/target/{}'.format(target_id))
        else:
            res = self._api_call('get', '/v1/target')
        return res['data']

    def api_target_post(self, data):
        res = self._api_call('post', '/v1/target', data=data)
        return res['data']

    def api_target_put(self, data):
        res = self._api_call('put', '/v1/target/{}'.format(data['id']), data=data)
        return res['data']

    def api_target_delete(self, target_id):
        res = self._api_call('delete', '/v1/target/{}'.format(target_id))
        return res['data']

    # policy
    def api_policy_get(self, policy_id=None):
        if policy_id is not None:
            res = self._api_call('get', '/v1/policy/{}'.format(policy_id))
        else:
            res = self._api_call('get', '/v1/policy')
        return res['data']

    def api_policy_post(self, data):
        res = self._api_call('post', '/v1/policy', data=data)
        return res['data']

    def api_policy_put(self, data):
        res = self._api_call('put', '/v1/policy/{}'.format(data['id']), data=data)
        return res['data']

    def api_policy_delete(self, policy_id):
        res = self._api_call('delete', '/v1/policy/{}'.format(policy_id))
        return res['data']

    # user_target_policy
    def api_user_target_policy_get(self, user_target_policy_id=None):
        if user_target_policy_id is not None:
            res = self._api_call('get', '/v1/user_target_policy/{}'.format(user_target_policy_id))
        else:
            res = self._api_call('get', '/v1/user_target_policy')
        return res['data']

    def api_user_target_policy_post(self, data):
        res = self._api_call('post', '/v1/user_target_policy', data=data)
        return res['data']

    def api_user_target_policy_put(self, data):
        res = self._api_call('put', '/v1/user_target_policy/{}'.format(data['id']), data=data)
        return res['data']

    def api_user_target_policy_delete(self, user_target_policy_id):
        res = self._api_call('delete', '/v1/user_target_policy/{}'.format(user_target_policy_id))
        return res['data']

    # user_target
    def api_user_target_get(self, user_id=None):
        params = {}
        if user_id is not None:
            params['user_id'] = user_id
        res = self._api_call('get', '/v1/user_target', params=params)
        return res['data']

    # usermanage
    def api_usermanage_put(self, user_id, data):
        res = self._api_call('put', '/v1/user/manage/{}'.format(user_id), data=data)
        return res['data']

    # policymanage
    def api_policymanage_put(self, policy_id=None, data=None):
        if policy_id is not None:
            res = self._api_call('put', '/v1/policy/manage/{}'.format(policy_id), data=data)
        else:
            res = self._api_call('put', '/v1/policy/manage', data=data)

        return res['data']
