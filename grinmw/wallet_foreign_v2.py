# Authors: xiaojay@gmail.com, Blade M. Doyle, Marek Narozniak
#
# Routines for working with Grin Wallet Foreign API V1


import os, requests, json

from grinmw.wallet_v3 import WalletError

class WalletForeignV1:
    def __init__(self, api_url, api_user, api_password):
        self.api_url = api_url
        self.api_user = api_user
        self.api_password = api_password

    def post(self, method, params):
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': method,
            'params': params
        }
        response = requests.post(
                self.api_url, json=payload,
                auth=(self.api_user, self.api_password))
        if response.status_code >= 300 or response.status_code < 200:
            # Requests-level error
            raise WalletError(method, params, response.status_code, response.reason)
        response_json = response.json()
        if "error" in response_json:
            # One version of a wallet error
            raise WalletError(
                method, params, response_json["error"]["code"], response_json["error"]["message"])
        if "Err" in response_json:
            # Another version of a wallet error
            raise WalletError(method, params, None, response_json["result"]["Err"])
        return response_json

    # methods
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/struct.Foreign.html#method.build_coinbase
    def build_coinbase(self, block_fees):
        resp = self.post('build_coinbase', [block_fees])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/struct.Foreign.html#method.check_version
    def check_version(self):
        resp = self.post('check_version', [])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/struct.Foreign.html#method.finalize_tx
    def finalize_tx(self, slate, post_automatically=False):
        resp = self.post('finalize_tx', [slate, post_automatically])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/struct.Foreign.html#method.receive_tx
    def receive_tx(self, slate, dest_acct_name=None, r_addr=None):
        resp = self.post('receive_tx', [slate, dest_acct_name, r_addr])
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/struct.Foreign.html#method.set_tor_config
    def set_tor_config(self, tor_config):
        resp = self.post('set_tor_config', [tor_config])
        return resp["result"]["Ok"]


