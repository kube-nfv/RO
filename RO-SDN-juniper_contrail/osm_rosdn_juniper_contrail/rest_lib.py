# Copyright 2020 ETSI
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import requests
import json
import copy
import logging

from time import time
from requests.exceptions import ConnectionError

class HttpException(Exception):
    pass


class NotFound(HttpException):
    pass


class AuthError(HttpException):
    pass


class DuplicateFound(HttpException):
    pass


class ServiceUnavailableException(HttpException):
    pass


class ContrailHttp(object):

    def __init__(self, auth_info, logger):
        self._logger = logger
        # default don't verify client cert
        self._ssl_verify = False
        # auth info: must contain auth_url and auth_dict
        self.auth_url = auth_info["auth_url"]
        self.auth_dict = auth_info["auth_dict"]

        self.max_retries = 3

        # Default token timeout
        self.token_timeout = 3500
        self.token = None
        # TODO - improve configuration timeouts

    def get_cmd(self, url, headers):
        self._logger.debug("")
        resp = self._request("GET", url, headers)
        return resp.json()

    def post_headers_cmd(self, url, headers, post_fields_dict=None):
        self._logger.debug("")
        # obfuscate password before logging dict
        if post_fields_dict.get('auth', {}).get('identity', {}).get('password', {}).get('user', {}).get('password'):
            post_fields_dict_copy = copy.deepcopy(post_fields_dict)
            post_fields_dict['auth']['identity']['password']['user']['password'] = '******'
            json_data_log = post_fields_dict_copy
        else:
            json_data_log = post_fields_dict
        self._logger.debug("Request POSTFIELDS: {}".format(json.dumps(json_data_log)))
        resp = self._request("POST_HEADERS", url, headers, data=post_fields_dict)
        return resp.text

    def post_cmd(self, url, headers, post_fields_dict=None):
        self._logger.debug("")
        # obfuscate password before logging dict
        if post_fields_dict.get('auth', {}).get('identity', {}).get('password', {}).get('user', {}).get('password'):
            post_fields_dict_copy = copy.deepcopy(post_fields_dict)
            post_fields_dict['auth']['identity']['password']['user']['password'] = '******'
            json_data_log = post_fields_dict_copy
        else:
            json_data_log = post_fields_dict
        self._logger.debug("Request POSTFIELDS: {}".format(json.dumps(json_data_log)))
        resp = self._request("POST", url, headers, data=post_fields_dict)
        return resp.text

    def delete_cmd(self, url, headers):
        self._logger.debug("")
        resp = self._request("DELETE", url, headers)
        return resp.text

    def _get_token(self, headers):
        self._logger.debug('Current Token:'.format(self.token))
        auth_url = self.auth_url + 'auth/tokens'
        if self.token is None or self._token_expired():
            if not self.auth_url:
                self.token = ""
            resp = self._request_noauth(url=auth_url, op="POST", headers=headers,
                                                 data=self.auth_dict)
            self.token = resp.headers.get('x-subject-token')
            self.last_token_time = time.time()
            self._logger.debug('Obtained token: '.format(self.token))

            return self.token

    def _token_expired(self):
        current_time = time.time()
        if self.last_token_time and (current_time - self.last_token_time < self.token_timeout):
            return False
        else:
            return True

    def _request(self, op, url, http_headers, data=None, retry_auth_error=True):
        headers = http_headers.copy()

        # Get authorization (include authentication headers)
        # todo - añadir token de nuevo
        #token = self._get_token(headers)
        token = None
        if token:
            headers['X-Auth-Token'] = token
        try:
            return self._request_noauth(op, url, headers, data)
        except AuthError:
            # If there is an auth error retry just once
            if retry_auth_error:
                return self._request(self, op, url, headers, data, retry_auth_error=False)

    def _request_noauth(self, op, url, headers, data=None):
        # Method to execute http requests with error control
        # Authentication error, always make just one retry
        # ConnectionError or ServiceUnavailable make configured retries with sleep between them
        # Other errors to raise:
        # - NotFound
        # - Conflict

        retry = 0
        while retry < self.max_retries:
            retry += 1

            # Execute operation
            try:
                self._logger.info("Request METHOD: {} URL: {}".format(op, url))
                if (op == "GET"):
                    resp = self._http_get(url, headers, query_params=data)
                elif (op == "POST"):
                    resp = self._http_post(url, headers, json_data=data)
                elif (op == "POST_HEADERS"):
                    resp = self._http_post_headers(url, headers, json_data=data)
                elif (op == "DELETE"):
                    resp = self._http_delete(url, headers, json_data=data)
                else:
                    raise HttpException("Unsupported operation: {}".format(op))
                self._logger.info("Response HTTPCODE: {}".format(resp.status_code))

                # Check http return code
                if resp:
                    return resp
                else:
                    status_code = resp.status_code
                    if status_code == 401:
                        # Auth Error - set token to None to reload it and raise AuthError
                        self.token = None
                        raise AuthError("Auth error executing operation")
                    elif status_code == 409:
                        raise DuplicateFound("Duplicate resource url: {}, response: {}".format(url, resp.text))
                    elif status_code == 404:
                        raise NotFound("Not found resource url: {}, response: {}".format(url, resp.text))
                    elif resp.status_code in [502, 503]:
                        if not self.max_retries or retry >= self.max_retries:
                            raise ServiceUnavailableException("Service unavailable error url: {}".format(url))

                        continue
                    else:
                        raise HttpException("Error status_code: {}, error_text: {}".format(resp.status_code, resp.text))

            except ConnectionError as e:
                self._logger.error("Connection error executing request: {}".format(repr(e)))
                if not self.max_retries or retry >= self.max_retries:
                    raise ConnectionError
                continue
            except Exception as e:
                self._logger.error("Error executing request: {}".format(repr(e)))
                raise e

    def _http_get(self, url, headers, query_params=None):
        return requests.get(url, headers=headers, params=query_params)

    def _http_post_headers(self, url, headers, json_data=None):
        return requests.head(url, json=json_data, headers=headers, verify=False)

    def _http_post(self, url, headers, json_data=None):
        return requests.post(url, json=json_data, headers=headers, verify=False)

    def _http_delete(self, url, headers, json_data=None):
        return requests.delete(url, json=json_data, headers=headers)

