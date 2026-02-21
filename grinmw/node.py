# Authors: xiaojay@gmail.com, Blade M. Doyle
#
# Routines for working with Grin node API V2
# https://github.com/mimblewimble/grin-rfcs/blob/master/text/0007-node-api-v2.md
#

from typing import List
import os, requests, json
from requests.auth import HTTPBasicAuth


# Exception class to hold wallet call error data
class NodeError(Exception):
    def __init__(self, method, params, code, reason, api_type):
        self.method = method
        self.params = params
        self.code = code  # may be None, not all errors have a code
        self.reason = reason
        self.api_type = api_type
        super().__init__(self.reason)

    def __str__(self):
        return f"Calling {self.api_type} api {self.method} with params {self.params} failed with error code {self.code} because: {self.reason}"


class NodeV2Foreign:
    def __init__(self, api_url, api_user, api_password):
        self.api_url = api_url
        self.api_user = api_user
        self.api_password = api_password

    def post(self, method, params):
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}

        response = requests.post(
            self.api_url, json=payload, auth=(self.api_user, self.api_password)
        )

        if response.status_code >= 300 or response.status_code < 200:
            # Requests-level error
            raise NodeError(
                method, params, response.status_code, response.reason, api_type
            )
        response_json = response.json()

        return response_json

    # Foreign API methods

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_block
    def get_block(self, height=None, hash_=None, commit=None):
        resp = self.post("get_block", [height, hash_, commit])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_header
    def get_header(self, height=None, hash_=None, commit=None):
        resp = self.post("get_header", [height, hash_, commit])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_blocks
    def get_blocks(self, start_height, end_height, max_, include_proof=False):
        resp = self.post("get_blocks", [start_height, end_height, max_, include_proof])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_version
    def get_version(self):
        resp = self.post("get_version", [])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_tip
    def get_tip(self):
        resp = self.post("get_tip", [])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_kernel
    def get_kernel(self, kernel, min_height=None, max_height=None):
        """
        if kernel not found: {'id': 1, 'jsonrpc': '2.0', 'result': {'Err': 'NotFound'}}
        return None
        """
        resp = self.post("get_kernel", [kernel, min_height, max_height])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_outputs
    def get_outputs(
        self,
        commits: List[str],
        start_height=None,
        end_height=None,
        include_proof=None,
        include_merkle_proof=None,
    ):
        resp = self.post(
            "get_outputs",
            [commits, start_height, end_height, include_proof, include_merkle_proof],
        )
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_unspent_outputs
    def get_unspent_outputs(
        self, start_index: int, max_: int, end_index=None, include_proof=False
    ):
        resp = self.post(
            "get_unspent_outputs", [start_index, end_index, max_, include_proof]
        )
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_pmmr_indices
    def get_pmmr_indices(self, start_block_height: int, end_block_height=None):
        resp = self.post("get_pmmr_indices", [start_block_height, end_block_height])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_pool_size
    def get_pool_size(self):
        resp = self.post("get_pool_size", [])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_stempool_size
    def get_stempool_size(self):
        resp = self.post("get_stempool_size", [])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.get_unconfirmed_transactions
    def get_unconfirmed_transactions(self):
        resp = self.post("get_unconfirmed_transactions", [])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/foreign_rpc/trait.ForeignRpc.html#tymethod.push_transaction
    def push_transaction(self, tx: dict, fluff=False):
        resp = self.post("push_transaction", [tx, fluff])
        return resp["result"].get("Ok")


class NodeV2Owner:
    def __init__(self, api_url, api_user, api_password):
        self.api_url = api_url
        self.api_user = api_user
        self.api_password = api_password

    def post(self, method, params):
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}

        response = requests.post(
            self.api_url, json=payload, auth=(self.api_user, self.api_password)
        )

        if response.status_code >= 300 or response.status_code < 200:
            # Requests-level error
            raise NodeError(
                method, params, response.status_code, response.reason, api_type
            )
        return response.json()

    # Owner API methods

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.get_status
    def get_status(self):
        resp = self.post("get_status", [])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.validate_chain
    def validate_chain(self, assume_valid_rangeproofs_kernels: bool):
        resp = self.post("validate_chain", [assume_valid_rangeproofs_kernels])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.compact_chain
    def compact_chain(self):
        resp = self.post("compact_chain", [])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.reset_chain_head
    def reset_chain_head(self, hash_: str):
        resp = self.post("reset_chain_head", [hash_])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.invalidate_header
    def invalidate_header(self, hash_: str):
        resp = self.post("invalidate_header", [hash_])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.get_peers
    def get_peers(self, peer_addr=None):
        params = []
        if peer_addr is not None:
            params.append(peer_addr)
        resp = self.post("get_peers", params)
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.get_connected_peers
    def get_connected_peers(self):
        resp = self.post("get_connected_peers", [])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.ban_peer
    def ban_peer(self, peer_addr: str):
        resp = self.post("ban_peer", [peer_addr])
        return resp["result"].get("Ok")

    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.unban_peer
    def unban_peer(self, peer_addr: str):
        resp = self.post("unban_peer", [peer_addr])
        return resp["result"].get("Ok")
