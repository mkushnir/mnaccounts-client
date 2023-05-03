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

        rv = self._auth_call(
            'post', '/account', data=data, retry_on_error=(not force))

        uinfo = rv['data']

        target = uinfo['target']

        u = urlsplit(target['url'])

        self._api_url = '{}://{}'.format(u.scheme, u.neloc)

    def _uinfo(self, force=False):
        if not force and (self._uinfo is not None):
            return self._uinfo

        rv = self._auth_call('get', '/account')
        self._uinfo = rv['data']
