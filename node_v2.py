# Authors: xiaojay@gmail.com, Blade M. Doyle
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


class NodeV2:
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

        #https://github.com/mimblewimble/grin-rfcs/blob/master/text/0007-node-api-v2.md#errors
        if "error" in response_json:
            # One version of a node error
            raise NodeError(method, params, response_json["error"]["code"], response_json["error"]["message"], api_type)
        if "Err" in response_json:
            # Another version of a node error
            raise NodeError(method, params, None, response_json["result"]["Err"], api_type)
        return response_json

    
    def get_status(self):
        resp = self.post('get_status', {}, 'owner')
        return resp["result"]["Ok"]

    def get_block(self, height=None, hash_=None, commit=None):
        resp = self.post('get_block', [height, hash_, commit], 'foreign')
        return resp["result"]["Ok"]
    
    def get_header(self, height=None, hash_=None, commit=None):
        resp = self.post('get_header', [height, hash_, commit], 'foreign')
        return resp["result"]["Ok"]

if __name__ == '__main__':
    import pprint
    from pathlib import Path
    home = str(Path.home())

    pp = pprint.PrettyPrinter(indent=4)
    owner_api_url = 'http://localhost:3413/v2/owner'
    #change to your grin owner_api sercret file
    owner_api_sercet_file = os.path.join(home, '.grin/main/.api_secret')
    owner_api_user = 'grin'
    owner_api_password = open(owner_api_sercet_file).read().strip()

    foreign_api_url = 'http://localhost:3413/v2/foreign'
    #change to your grin owner_api sercret file
    foreign_api_sercet_file = os.path.join(home, '.grin/main/.foreign_api_secret')
    foreign_api_user = 'grin'
    foreign_api_password = open(foreign_api_sercet_file).read().strip()

    node = NodeV2( foreign_api_url, foreign_api_user, foreign_api_password, owner_api_url, owner_api_user, owner_api_password)
    pp.pprint(node.get_status())
    #pp.pprint(node.get_block(1036985))
    #pp.pprint(node.get_block(None, '00010b5eb1b657e0155ecc37bbde8ca574a7260112354c3439318a466dff475f'))
    #pp.pprint(node.get_block(None, None, '0852b0a613a1cf85752459af1e6ebd949d32648883cb32a8f6c3e55c0d0769eeea'))

    pp.pprint(node.get_header(1036985))


