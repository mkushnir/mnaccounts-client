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
            503,
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


class _MNAccountAPIClientBase:
    """Base for account service clients."""

    _session_cookie_file = '.mnaccountapiclient.cookie'

    def __init__(self, auth_url, creds, session_params=None):
        if session_params is None:
            session_params = {}

        self._session = _requests_retry_session(**session_params)

        if os.path.exists(self._session_cookie_file):
            with open(self._session_cookie_file, 'rb') as f:
                saved_cookie = pickle.load(f)
                self._session.cookies.update(saved_cookie)

        self._auth_url = auth_url
        self._api_url = None
        self._creds = creds
        self._login()

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
                try:
                    res = response.json()

                except Exception:
                    res = response.text

                raise Exception('http error: code {} data {}'.format(
                    response.status_code, res))

        else:
            try:
                res = response.json()

            except Exception:
                res = response.text

            raise Exception('http error: code {} data {}'.format(
                response.status_code, res))

    def _auth_call(self, method, endpoint, params=None, data=None, retry_on_error=True):
        return self._call(self._auth_url, method, endpoint, params, data, retry_on_error)

    def _api_call(self, method, endpoint, params=None, data=None, retry_on_error=True):
        return self._call(self._api_url, method, endpoint, params, data, retry_on_error)

    def _api_url_from_uinfo(self, uinfo):
        target = uinfo['target']
        u = urlsplit(target['url'])
        self._api_url = '{}://{}'.format(u.scheme, u.netloc)

    def _login(self, force=False):
        if ('session' in self._session.cookies) and \
                (self._api_url is not None) and \
                not force:
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

        rv = self._auth_call(
            'post', '/account', data=data, retry_on_error=(not force))

        uinfo = rv['data']

        self._api_url_from_uinfo(uinfo)
