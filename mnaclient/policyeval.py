"""Policy evaluation routine."""

from . import _policyeval_builtins

_globals = {
    '__builtins__': _policyeval_builtins
}

def _policy_predicate_eval(locals_, tag_, pred_):
    """Evaluate a policy predicate.

    :Parameters:
        - locals_: local context of the "eval" call;

        - tag_: the statement's tag;

        - pred_: the statement's predicate subject to  evaluation.

    :Return:
        tuple of (tag, result) where tag is the tag_ passed, and result is a boolean result of the "eval()" call.

    :Exception:
        - AssertionError in case result is not a boolean value;

        - any exception that may be raised in the predicate.
    """
    res = eval(pred_, _globals, locals_)

    if type(res) is list:
        return tag_, res

    assert type(res) is bool, '{} does not evaluate to bool'.format(pred_)
    return tag_, res
