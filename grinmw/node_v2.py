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

    # Foreign API methods

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_block
    def get_block(self, height=None, hash_=None, commit=None):
        resp = self.post('get_block', [height, hash_, commit], 'foreign')
        return resp["result"]["Ok"]

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_header
    def get_header(self, height=None, hash_=None, commit=None):
        resp = self.post('get_header', [height, hash_, commit], 'foreign')
        return resp["result"]["Ok"]

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_blocks
    def get_blocks(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_version
    def get_version(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_tip
    def get_tip(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_kernel
    def get_kernel(self, kernel, min_height=None, max_height=None):
        '''
        if kernel not found: {'id': 1, 'jsonrpc': '2.0', 'result': {'Err': 'NotFound'}}
        return None
        '''
        resp = self.post('get_kernel', [kernel, min_height, max_height], 'foreign')
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_outputs
    def get_outputs(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_unspent_outputs
    def get_unspent_outputs(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_pmmr_indices
    def get_pmmr_indices(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_pool_size
    def get_pool_size(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_stempool_size
    def get_stempool_size(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_unconfirmed_transactions
    def get_unconfirmed_transaction(self):
        pass # TODO

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.push_transaction
    def push_transaction(self):
        pass # TODO

    # Owner API methods

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.get_status
    def get_status(self):
        pass

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.validate_chain
    def validate_chain(self):
        pass

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.compact_chain
    def compact_chain(self):
        pass

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.reset_chain_head
    def reset_chain_head(self):
        pass

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.invalidate_header
    def invalidate_header(self):
        pass

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.get_peers
    def get_peers(self):
        pass

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.get_connected_peers
    def get_connected_peers(self):
        pass

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.ban_peer
    def ban_peer(self):
        pass

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.unban_peer
    def unban_peer(self):
        pass
