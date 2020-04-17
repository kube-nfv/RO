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

from io import BytesIO
import pycurl
import json
import copy

class HttpException(Exception):
    pass

class NotFound(HttpException):
    pass

class Http(object):

    def __init__(self, logger):
        self._logger = logger
        self._response_headers = None


    def _check_http_response(self, http_code, data):
        if http_code >= 300:
            resp = ""
            if data.getvalue():
                data_text = data.getvalue().decode()
                self._logger.info("Response {} DATA: {}".format(http_code, data_text))
                resp = ": " + data_text
            else:
                self._logger.info("Response {}".format(http_code))
            if http_code == 404:
                raise NotFound("Error {}{}".format(http_code, resp))
            raise HttpException("Error {}{}".format(http_code, resp))


    def _get_curl_cmd(self, url, headers):
        self._logger.debug("")
        curl_cmd = pycurl.Curl()
        curl_cmd.setopt(pycurl.URL, url)
        curl_cmd.setopt(pycurl.SSL_VERIFYPEER, 0)
        curl_cmd.setopt(pycurl.SSL_VERIFYHOST, 0)
        if headers:
            curl_cmd.setopt(pycurl.HTTPHEADER, headers)
        return curl_cmd


    def get_cmd(self, url, headers):
        self._logger.debug("")
        data = BytesIO()
        curl_cmd = self._get_curl_cmd(url, headers)
        curl_cmd.setopt(pycurl.HTTPGET, 1)
        curl_cmd.setopt(pycurl.WRITEFUNCTION, data.write)
        self._logger.info("Request METHOD: {} URL: {}".format("GET", url))
        curl_cmd.perform()
        http_code = curl_cmd.getinfo(pycurl.HTTP_CODE)
        self._logger.info("Response HTTPCODE: {}".format(http_code))
        curl_cmd.close()
        if data.getvalue():
            data_text = data.getvalue().decode()
            self._logger.debug("Response DATA: {}".format(data_text))
            return http_code, data_text
        return http_code, None


    def delete_cmd(self, url, headers):
        self._logger.debug("")
        data = BytesIO()
        curl_cmd = self._get_curl_cmd(url, headers)
        curl_cmd.setopt(pycurl.CUSTOMREQUEST, "DELETE")
        curl_cmd.setopt(pycurl.WRITEFUNCTION, data.write)
        self._logger.info("Request METHOD: {} URL: {}".format("DELETE", url))
        curl_cmd.perform()
        http_code = curl_cmd.getinfo(pycurl.HTTP_CODE)
        self._logger.info("Response HTTPCODE: {}".format(http_code))
        curl_cmd.close()
        self._check_http_response(http_code, data)
        # TODO 202 accepted should be returned somehow
        if data.getvalue():
            data_text = data.getvalue().decode()
            self._logger.debug("Response DATA: {}".format(data_text))
            return http_code, data_text
        else:
            self._logger.debug("Response DATA: NONE")
            return http_code, None


    def header_function(self, header_line):
        header_line = header_line.decode('iso-8859-1')
        if ':' not in header_line:
            return
        name, value = header_line.split(':', 1)
        name = name.strip()
        value = value.strip()
        name = name.lower()
        self._response_headers[name] = value


    def post_cmd(self, url, headers, postfields_dict=None, return_header=None):
        self._logger.debug('url: {}, headers: {}, postfields_dict: {}, return_header: {}'.format(url, headers, postfields_dict, return_header))
        data = BytesIO()
        curl_cmd = self._get_curl_cmd(url, headers)
        curl_cmd.setopt(pycurl.POST, 1)
        curl_cmd.setopt(pycurl.WRITEFUNCTION, data.write)
        if return_header:
            self._response_headers = {}
            curl_cmd.setopt(pycurl.HEADERFUNCTION, self.header_function)

        jsondata = json.dumps(postfields_dict)
        if postfields_dict.get('auth',{}).get('identity',{}).get('password',{}).get('user',{}).get('password'):
            postfields_dict_copy = copy.deepcopy(postfields_dict)
            postfields_dict_copy['auth']['identity']['password']['user']['password'] = '******'
            jsondata_log = json.dumps(postfields_dict_copy)
        else:
            jsondata_log = jsondata
        self._logger.debug("Request POSTFIELDS: {}".format(jsondata_log))
        curl_cmd.setopt(pycurl.POSTFIELDS, jsondata)

        self._logger.info("Request METHOD: {} URL: {}".format("POST", url))
        curl_cmd.perform()
        http_code = curl_cmd.getinfo(pycurl.HTTP_CODE)
        self._logger.info("Response HTTPCODE: {}".format(http_code))
        curl_cmd.close()
        if return_header:
            data_text = self._response_headers.get(return_header)
            self._logger.debug("Response HEADER: {}".format(data_text))
            return http_code, data_text
        if data.getvalue():
            data_text = data.getvalue().decode()
            self._logger.debug("Response DATA: {}".format(data_text))
            return http_code, data_text
        else:
            return http_code, None

