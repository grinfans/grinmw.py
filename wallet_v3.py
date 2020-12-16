# Copyright 2020 xiaojay@gmail.com and Blade M. Doyle
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# Routines for working with Grin Wallet Owner API V3
#

import os, requests, json
from requests.auth import HTTPBasicAuth
from ecies.utils import generate_key
from coincurve import PrivateKey, PublicKey
from Crypto.Cipher import AES
import base64

def encrypt(key, msg, nonce):
    '''key hex string; msg string; nonce 12bit bytes'''
    aes_cipher = AES.new(bytes.fromhex(key), AES.MODE_GCM, nonce=nonce)
    msg = str.encode(msg)
    ciphertext, auth_tag = aes_cipher.encrypt_and_digest(msg)
    return base64.b64encode(ciphertext + auth_tag).decode()

def decrypt(key, data, nonce):
    data = base64.b64decode(data)
    ciphertext = data[:-16]
    auth_tag = data[-16:]
    aesCipher = AES.new(bytes.fromhex(key), AES.MODE_GCM, nonce=nonce)
    plaintext = aesCipher.decrypt(ciphertext)
    return plaintext.decode()


# Exception class to hold wallet call error data
class WalletError(Exception):
    def __init__(self, method, params, code, reason):
        self.method = method
        self.params = params
        self.code = code
        self.reason = reason
        super().__init__(self.reason)

    def __str__(self):
        return f'Callng {self.method} with params {self.params} failed with error code {self.code} because: {self.reason}'


# Grin Wallet Owner API V3
class WalletV3:
    def __init__(self, api_url, api_user, api_password):
        self.api_url = api_url
        self.api_user = api_user
        self.api_password = api_password

        self.key = generate_key()
        self.share_secret = ''
        self.token = ''

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
            raise WalletError(method, params, response_json["error"]["code"], response_json["error"]["message"])
        if "Err" in response_json:
            # Another version of a wallet error
            raise WalletError(method, params, None, response_json["result"]["Err"])
        return response_json

    def post_encrypted(self, method, params):
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': method,
            'params': params
        }
        nonce = os.urandom(12)
        encrypted = encrypt(self.share_secret, json.dumps(payload), nonce)
        resp = self.post('encrypted_request_v3', {
            'nonce': nonce.hex(),
            'body_enc': encrypted
        })
        nonce2 = bytes.fromhex(resp['result']['Ok']['nonce'])
        encrypted2 = resp['result']['Ok']['body_enc']
        response_json = json.loads(decrypt(self.share_secret, encrypted2, nonce2))
        if "error" in response_json:
            # One version of a wallet error
            raise WalletError(method, params, response_json["error"]["code"], response_json["error"]["message"])
        if "Err" in response_json:
            # Another version of a wallet error
            raise WalletError(method, params, None, response_json["result"]["Err"])
        return response_json

    ##
    # The API: https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.init_secure_api
    def init_secure_api(self):
        pubkey = self.key.public_key.format().hex()
        resp = self.post('init_secure_api', {'ecdh_pubkey': pubkey})
        remote_pubkey = resp['result']['Ok']
        self.share_secret = PublicKey(bytes.fromhex(remote_pubkey)).multiply(self.key.secret).format().hex()[2:]

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.open_wallet
    def open_wallet(self, name, password):
        params = {
                'name': name,
                'password': password,
            }
        resp = self.post_encrypted('open_wallet', params)
        self.token = resp['result']['Ok']

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.node_height
    def node_height(self):
        params = { 'token': self.token }
        resp = self.post_encrypted('node_height', params)
        return resp['result']['Ok']

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.retrieve_txs
    def retrieve_txs(self, tx_id=None, tx_slate_id=None, refresh=True):
        params = {
                'token': self.token,
                'refresh_from_node': refresh,
                'tx_id': tx_id,
                'tx_slate_id': tx_slate_id,
            }
        resp = self.post_encrypted('retrieve_txs', params)
        if refresh and not resp["result"]["Ok"][0]:
            # We requested refresh but data was not successfully refreshed
            raise WalletError("retrieve_outputs", params, None, "Failed to refresh data from the node")
        return resp["result"]["Ok"][1]

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.retrieve_outputs
    def retrieve_outputs(self, include_spent=False, tx_id=None, refresh=True):
        params = {
                'token': self.token,
                'include_spent': include_spent,
                'refresh_from_node': refresh,
                'tx_id': tx_id,
            }
        resp = self.post_encrypted('retrieve_outputs', params)
        if refresh and not resp["result"]["Ok"][0]:
            # We requested refresh but data was not successfully refreshed
            raise WalletError("retrieve_outputs", params, None, "Failed to refresh data from the node")
        return resp["result"]["Ok"][1]

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.retrieve_summary_info
    def retrieve_summary_info(self, minimum_confirmations=1, refresh=True):
        params = {
                'token': self.token,
                'minimum_confirmations': minimum_confirmations,
                'refresh_from_node': refresh,
            }
        resp = self.post_encrypted('retrieve_summary_info', params)
        if refresh and not resp["result"]["Ok"][0]:
            # We requested refresh but data was not successfully refreshed
            raise WalletError("retrieve_outputs", params, None, "Failed to refresh data from the node")




    # -- WIP: XXX TODO -- Complete Implementation

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.cancel_tx
    def cancel_tx(self, tx_id=None, tx_slate_id=None):
        params = {
                'token': self.token,
                'tx_id': tx_id,
                'tx_slate_id': tx_slate_id,
            }
        raise WalletError("cancel_tx", params, None, "Not Yet Implemented")

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.scan
    def scan(self, start_height=0, delete_unconfirmed=False):
        params = {
                'token': self.token,
                'start_height': start_height,
                'delete_unconfirmed': delete_unconfirmed,
            }
        raise WalletError("scan", params, None, "Not Yet Implemented")
    

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.finalize_tx
    def finalize_tx(self, slate):
        params = {
                'token': self.token,
                'slate': slate,
            }
        raise WalletError("finalize_tx", params, None, "Not Yet Implemented")

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_stored_tx
    def get_stored_tx(self, id=None, slate_id=None):
        params = {
                'token': self.token,
                'id': id,
                'slate_id': slate_id,
            }
        raise WalletError("get_stored_tx", params, None, "Not Yet Implemented")

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.init_send_tx
    def init_send_tx(self, args):
        params = {
                'token': self.token,
                'args': args,
            }
        raise WalletError("init_send_tx", params, None, "Not Yet Implemented")

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.issue_invoice_tx
    def issue_invoice_tx(self, args):
        params = {
                'token': self.token,
                'args': args,
            }
        raise WalletError("issue_invoice_tx", params, None, "Not Yet Implemented")

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.post_tx
    def post_tx(self, slate, fluff=False):
        params = {
                'token': self.token,
                'slate': slate,
                'fluff': fluff,
            }
        raise WalletError("post_tx", params, None, "Not Yet Implemented")

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.process_invoice_tx
    def process_invoice_tx(self, slate, args):
        params = {
                'token': self.token,
                'slate': slate,
                'args': args,
            }
        raise WalletError("process_invoice_tx", params, None, "Not Yet Implemented")

    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.tx_lock_outputs
    def tx_lock_outputs(self, slate):
        params = {
                'token': self.token,
                'slate': slate,
            }
        raise WalletError("tx_lock_outputs", params, None, "Not Yet Implemented")

    # More....
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.accounts
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.change_password
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.close_wallet
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.create_account_path
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.create_config
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.create_slatepack_message
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.delete_wallet
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_mnemonic
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_slatepack_address
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_slatepack_secret_key
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_top_level_directory
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_updater_messages
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.retrieve_payment_proof
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.set_active_account
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.set_top_level_directory
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.set_tor_config
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.slate_from_slatepack_message
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.start_updater
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.stop_updater
    # https://docs.rs/grin_wallet_api/4.0.0/grin_wallet_api/trait.OwnerRpc.html#tymethod.verify_payment_proof


if __name__ == '__main__':
    import pprint
    pp = pprint.PrettyPrinter(indent=4)
    api_url = 'http://localhost:3420/v3/owner'
    #change to your grin owner_api sercret file
    api_sercet_file = '/Users/yuanjieyang/.grin/main/.owner_api_secret'
    api_user = 'grin'
    api_password = open(api_sercet_file).read().strip()
    wallet = WalletV3(api_url, api_user, api_password)
    wallet.init_secure_api()


    #change to you wallet password
    wallet_password = '123'

    wallet.open_wallet(None, wallet_password)
    pp.pprint(wallet.node_height())
    #pp.pprint(wallet.retrieve_txs(tx_id="x"))
    pp.pprint(wallet.retrieve_txs())


    # test:  invalid api_sercet_file
    # test:  invalid api_user
    # test:  invalid api_password
    # test:  invalid wallet_password
    # test:  invalid params for each method
    #        ex:   wallet.retrieve_txs(tx_id="x")
