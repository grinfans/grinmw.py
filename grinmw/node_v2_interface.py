# Authors: xiaojay@gmail.com, Blade M. Doyle, Marek Narozniak
#
# Routines for working with Grin node API V2
# https://github.com/mimblewimble/grin-rfcs/blob/master/text/0007-node-api-v2.md
#

import os, requests, json

from requests.auth import HTTPBasicAuth

# Exception class to hold wallet call error data
class NodeError(Exception):
    def __init__(self, method, params, code, reason, api_type):
        self.method = method
        self.params = params
        self.code = code    # may be None, not all errors have a code
        self.reason = reason
        self.api_type = api_type
        super().__init__(self.reason)

    def __str__(self):
        return f'Calling {self.api_type} api {self.method} with params {self.params} failed with error code {self.code} because: {self.reason}'

class NodeV2Interface:
    def __init__(self, foreign_api_url, foreign_api_user, foreign_api_password, owner_api_url, owner_api_user, owner_api_password):
        self.foreign_api_url = foreign_api_url
        self.foreign_api_user = foreign_api_user
        self.foreign_api_password = foreign_api_password

        self.owner_api_url = owner_api_url
        self.owner_api_user = owner_api_user
        self.owner_api_password = owner_api_password


    def post(self, method, params, api_type):
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': method,
            'params': params
        }

        if api_type == 'foreign':
            response = requests.post(
                    self.foreign_api_url, json=payload,
                    auth=(self.foreign_api_user, self.foreign_api_password))
        elif api_type == 'owner':
            response = requests.post(
                    self.owner_api_url, json=payload,
                    auth=(self.owner_api_user, self.owner_api_password))
        else:
            pass

        if response.status_code >= 300 or response.status_code < 200:
            # Requests-level error
            raise NodeError(method, params, response.status_code, response.reason, api_type)
        response_json = response.json()

        # https://github.com/mimblewimble/grin-rfcs/blob/master/text/0007-node-api-v2.md#errors
        if "error" in response_json:
            # One version of a node error
            raise NodeError(method, params, response_json["error"]["code"], response_json["error"]["message"], api_type)
        if "Err" in response_json:
            # Another version of a node error
            raise NodeError(method, params, None, response_json["result"]["Err"], api_type)
        return response_json
