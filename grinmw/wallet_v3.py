# Authors: xiaojay@gmail.com, Blade M. Doyle
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
        self.code = code    # may be None, not all errors have a code
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
    # The API: https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.init_secure_api
    def init_secure_api(self):
        pubkey = self.key.public_key.format().hex()
        resp = self.post('init_secure_api', {'ecdh_pubkey': pubkey})
        remote_pubkey = resp['result']['Ok']
        self.share_secret = PublicKey(bytes.fromhex(remote_pubkey)).multiply(self.key.secret).format().hex()[2:]
        return self.share_secret

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.open_wallet
    def open_wallet(self, name, password):
        params = {
                'name': name,
                'password': password,
            }
        resp = self.post_encrypted('open_wallet', params)
        self.token = resp['result']['Ok']
        return self.token

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.node_height
    def node_height(self):
        params = { 'token': self.token }
        resp = self.post_encrypted('node_height', params)
        return resp['result']['Ok']

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.retrieve_txs
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

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.retrieve_outputs
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

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.retrieve_summary_info
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
        return resp["result"]["Ok"][1]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.cancel_tx
    def cancel_tx(self, tx_id=None, tx_slate_id=None, refresh=True):
        params = {
                'token': self.token,
                'tx_id': tx_id,
                'tx_slate_id': tx_slate_id,
            }
        resp = self.post_encrypted('cancel_tx', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.scan
    def scan(self, start_height=0, delete_unconfirmed=False):
        params = {
                'token': self.token,
                'start_height': start_height,
                'delete_unconfirmed': delete_unconfirmed,
            }
        resp = self.post_encrypted('scan', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.finalize_tx
    def finalize_tx(self, slate):
        params = {
                'token': self.token,
                'slate': slate,
            }
        resp = self.post_encrypted('finalize_tx', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_stored_tx
    def get_stored_tx(self, id=None, slate_id=None):
        params = {
                'token': self.token,
                'id': id,
                'slate_id': slate_id,
            }
        resp = self.post_encrypted('get_stored_tx', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.init_send_tx
    def init_send_tx(self, args):
        params = {
                'token': self.token,
                'args': args,
            }
        resp = self.post_encrypted('init_send_tx', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.issue_invoice_tx
    def issue_invoice_tx(self, args):
        params = {
                'token': self.token,
                'args': args,
            }
        resp = self.post_encrypted('issue_invoice_tx', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.post_tx
    def post_tx(self, slate, fluff=False):
        params = {
                'token': self.token,
                'slate': slate,
                'fluff': fluff,
            }
        resp = self.post_encrypted('post_tx', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.process_invoice_tx
    def process_invoice_tx(self, slate, args):
        params = {
                'token': self.token,
                'slate': slate,
                'args': args,
            }
        resp = self.post_encrypted('process_invoice_tx', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.tx_lock_outputs
    def tx_lock_outputs(self, slate):
        params = {
                'token': self.token,
                'slate': slate,
            }
        resp = self.post_encrypted('tx_lock_outputs', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.accounts
    def accounts(self):
        params = {
                'token': self.token,
            }
        resp = self.post_encrypted('accounts', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.change_password
    def change_password(self, old, new, name):
        params = {
                'name': name,
                'old': old,
                'new': new,
            }
        resp = self.post_encrypted('change_password', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.close_wallet
    def close_wallet(self, name=None):
        params = {
                'name': name,
            }
        resp = self.post_encrypted('close_wallet', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.create_account_path
    def create_account_path(self, label):
        params = {
                'token': self.token,
                'label': label,
            }
        resp = self.post_encrypted('create_account_path', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.create_config
    def create_config(self, chain_type="Mainnet", wallet_config=None, logging_config=None, tor_config=None):
        params = {
                'chain_type': chain_type,
                'wallet_config': wallet_config,
                'logging_config': logging_config,
                'tor_config': tor_config,
            }
        resp = self.post_encrypted('create_config', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.create_slatepack_message
    def create_slatepack_message(self, slate, recipients, sender_index=None):
        params = {
                'token': self.token,
                'slate': slate,
                'recipients': recipients,
                'sender_index': sender_index,
            }
        resp = self.post_encrypted('create_slatepack_message', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.delete_wallet
    def delete_wallet(self, name=None):
        params = {
                'name': name,
            }
        resp = self.post_encrypted('delete_wallet', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_mnemonic
    def get_mnemonic(self, password, name=None):
        params = {
                'name': name,
                'password': password,
            }
        resp = self.post_encrypted('get_mnemonic', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_slatepack_address
    def get_slatepack_address(self, derivation_index=0):
        params = {
                'token': self.token,
                'derivation_index': derivation_index,
            }
        resp = self.post_encrypted('get_slatepack_address', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_slatepack_secret_key
    def get_slatepack_secret_key(self, derivation_index=0):
        params = {
                'token': self.token,
                'derivation_index': derivation_index,
            }
        resp = self.post_encrypted('get_slatepack_secret_key', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_top_level_directory
    def get_top_level_directory(self):
        params = {}
        resp = self.post_encrypted('get_top_level_directory', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.get_updater_messages
    def get_updater_messages(self, count=1):
        params = {
                'count': count,
            }
        resp = self.post_encrypted('get_updater_messages', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.retrieve_payment_proof
    def retrieve_payment_proof(self, refresh=True, tx_id=None, tx_slate_id=None):
        params = {
                'token': self.token,
                'refresh_from_node': refresh_from_node,
                'tx_id': tx_id,
                'tx_slate_id': tx_slate_id,
            }
        resp = self.post_encrypted('retrieve_payment_proof', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.set_active_account
    def set_active_account(self, label):
        params = {
                'token': self.token,
                'label': label,
            }
        resp = self.post_encrypted('set_active_account', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.set_top_level_directory
    def set_top_level_directory(self, dir):
        params = {
                'dir': dir,
            }
        resp = self.post_encrypted('set_top_level_directory', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.set_tor_config
    def set_tor_config(self, tor_config=None):
        params = {
                'tor_config': tor_config,
            }
        resp = self.post_encrypted('set_tor_config', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.slate_from_slatepack_message
    def slate_from_slatepack_message(self, message, secret_indices):
        params = {
                'token': self.token,
                'message': message,
                'secret_indices': secret_indices,
            }
        resp = self.post_encrypted('slate_from_slatepack_message', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.start_updater
    def start_updater(self, frequency):
        params = {
                'token': self.token,
                'frequency': frequency,
            }
        resp = self.post_encrypted('start_updater', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.stop_updater
    def stop_updater(self):
        params = {}
        resp = self.post_encrypted('stop_updater', params)
        return resp

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.verify_payment_proof
    def verify_payment_proof(self, proof):
        params = {
                'token': self.token,
                'proof': proof,
            }
        resp = self.post_encrypted('verify_payment_proof', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.create_wallet
    def create_wallet(self, password, name=None, mnemonic=None, mnemonic_length=16):
        params = {
                'password': password,
                'name': name,
                'mnemonic': mnemonic,
                'mnemonic_length=': mnemonic_length,
            }
        resp = self.post_encrypted('create_wallet', params)
        return resp["result"]["Ok"]
