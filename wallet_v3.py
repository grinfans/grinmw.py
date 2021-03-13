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
        return True

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.scan
    def scan(self, start_height=0, delete_unconfirmed=False):
        params = {
                'token': self.token,
                'start_height': start_height,
                'delete_unconfirmed': delete_unconfirmed,
            }
        resp = self.post_encrypted('scan', params)
        return True
    
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
        return True

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
        return True

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
        return True

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.close_wallet
    def close_wallet(self, name=None):
        params = {
                'name': name,
            }
        resp = self.post_encrypted('close_wallet', params)
        return True

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
        return True

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
        return True

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
        return True

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.set_top_level_directory
    def set_top_level_directory(self, dir):
        params = {
                'dir': dir,
            }
        resp = self.post_encrypted('set_top_level_directory', params)
        return True

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.set_tor_config
    def set_tor_config(self, tor_config=None):
        params = {
                'tor_config': tor_config,
            }
        resp = self.post_encrypted('set_tor_config', params)
        return True

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
        return True

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.stop_updater
    def stop_updater(self):
        params = {}
        resp = self.post_encrypted('stop_updater', params)
        return True

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.verify_payment_proof
    def verify_payment_proof(self, proof):
        params = {
                'token': self.token,
                'proof': proof,
            }
        resp = self.post_encrypted('verify_payment_proof', params)
        return resp["result"]["Ok"]

    # https://docs.rs/grin_wallet_api/5.0.1/grin_wallet_api/trait.OwnerRpc.html#tymethod.create_wallet
    def create_wallet(self, password, name=None, mnemonic=None, mnemonic_length=0):
        params = {
                'password': password,
                'name': name,
                'mnemonic': mnemonic,
                'mnemonic_length=': mnemonic_length,
            }
        resp = self.post_encrypted('create_wallet', params)
        return resp["result"]["Ok"]



if __name__ == '__main__':
    import pprint
    pp = pprint.PrettyPrinter(indent=4)
    api_url = 'http://localhost:3420/v3/owner'
    #change to your grin owner_api sercret file
    api_sercet_file = '/home/ubuntu/.grin/main/.owner_api_secret'
    api_user = 'grin'
    api_password = open(api_sercet_file).read().strip()
    wallet = WalletV3(api_url, api_user, api_password)
    wallet.init_secure_api()


    #change to you wallet password
    wallet_password = '123'

    wallet.open_wallet(None, wallet_password)
    pp.pprint(wallet.node_height())
    #pp.pprint(wallet.retrieve_txs(tx_id="x"))
    #pp.pprint(wallet.retrieve_txs())
    pp.pprint(wallet.get_slatepack_address())
    
    #send to gate.io
    send_args = {
        'src_acct_name': None,
	'amount': int(2.67020546 * 1000000000),
	'minimum_confirmations': 10,
	'max_outputs': 500,
	'num_change_outputs': 1,
	'selection_strategy_is_use_all': False,
	'target_slate_version': None,
	'payment_proof_recipient_address': 'grin1n26np6apy07576qx6yz4qayuwxcpjvl87a2mjv3jpk6mnyz8y4vq65ahjm',
	'ttl_blocks': None,
	
    #https://github.com/mimblewimble/grin-wallet/blob/4e4880be8eff2e844c8e4eb72864e4bebb6b3831/libwallet/src/api_impl/types.rs#L86

        'send_args':{
            "dest": 'grin1n26np6apy07576qx6yz4qayuwxcpjvl87a2mjv3jpk6mnyz8y4vq65ahjm',
            "post_tx": True,
            "fluff": True,
            "skip_tor": False
        }
    }
    print(wallet.init_send_tx(send_args))
    '''
    {   'header_hash': '000246ab8089cb66076b904a52c704e4f05c966437ba25846d6f47d7764eba64',
    'height': '1129759',
    'updated_from_node': True}
'grin1n7nh7hz5nsx2rfuvw450x95xzxp7v7dhew2n7gsxj8atkl9fsjlqeeml0a'
{'coms': [{'c': '090128a0225cbc4e43ee5d046008adfd55c0fb1da5446ef756bdde7aa7e49d5535'}, {'c': '097c3926d228a2315995f832383243a25b310929a8800983379fcb467aa9146497', 'p': '3fcbdd69c01bfb3cea18dcfb84610343046f75c877ca59515729f5eda8b6e6b0eae919f29838e951df09115b5651c08dc14601524d7bfbfbb3896ca232629fdb0e38ef4fddc5f2cf6bf0152fdca49f04a9ca6b2063eecf0e02d71aaeefc70165c6a2cdf211b024746dbf6ef525d6cf65f52dd14561b6b2f46186c6a08b930890e054acdd29e1d8cfcdcd0cee038ab36d1ae3c86e40da155155cdd9c6056903b60d9ce44b96ab91142e60f26a69ec38f6f583b357bd11911df1aa41d4154065a8e992bbb29f42c2eacab2392f7e94bf6e9f226d0ea4a593dd5099f57a4ba416b2abd0e39487a5ce4f0ce62c3b3729e064c15dac6655a3b9ae9327a75da4f175e32b7ad93c326e0d1d60e7578def3030190f2eb1047bd093fd110a87e9715a30899d81d743c5b8aeeedde614952bab48c8eb8c72262b0fd3a4e4693167768edeaf76c801099a2eefcf98a3336a3888bbadb4c7bea8034598da777d3daeb495865eb11d031489918a4fa6984fcfa60dd4d05c8ed5456f874e5a4cb671c794a7c573ffdcfe98be4275a40fac9fcb74b3a8c0cae1efacd6cac3326c61fd8672a08694d17c6b6afd6325cb002c7d00a647fd1ae769bb9df0d052367837f649636f4b3a58980eeafe4d22f3bf0efae9bdb2213711a3464f355e3ad3e5857cc77bf72989b0f231da7f818adcde12a923c3cb40c7d1d6c0eceddd1eb8fe0c9ce60257972440f50c2f7f4cf620071d249b3587d55b5ee1611934c14526d2b20161ed3b91f597f59b3745015424c12c3e4345c12d281cabbe675a9a97484085fa3a91e6a2fbfe30788f3d92c8bd218be2542ca89ea9770999a2ccf8eef06c2fb4b71bd836be2379a861e3e53cc99f52795d1531ad85420732e4b60c0cbb2ea32db7fa178de9f450e159929561342ef525ac9f3a685c28f5f6c335a34ae797324c8b75142d4cd0f958'}, {'c': '08f2f4aa6aa4f6649cb0757f23c87b78d0a0afc367d683123642fe8c9de827bd7c', 'p': '3d233470487d855e9a57fe4a84b8f20ffad421a79f4f810492aa0c12fc06f2ff08b724af2dcca21ce9db10f68621cbe932cabe434e341da4df81fe298cc010fd08b7cf503308adc47e47abdd566261d10b6706a019da7409bdb3effcdb54952008f363c85dc75c9aefe75f8de4f272bdb7e6114dde337a25b32bc419947364dc05ecd109c90dd631ef874b0f7116c92ace5a20509471feb984135db2daec856b938ad112f77e7a57b7d5fd7fbfed2ad0940763129be60d34e6ba423bc492efff464f1aae96653690515db7f1114ce99d81d3620d3e8c885d800a974fcafb73dcfa20e303abcff64a14d51f7f99c72e38e774b41fa90dc2b70649d8259682e1bf25c184554650755d8e23c5d5a6987bacb8fed5b1af326334ade905c5edc882de6cc62465fd649c4bdf9f6ba223312fdcc6bdb17cd0731ba97cd73cc72167ef00689ee38094e900ec441a69ac0442bf617853eabd068f358d26fb885771485af5bdb201ef5fa893d63793b0d7caea1fc577248599af536f4dae023eb223a25584f1aeec169a8f349d1e6ae11125dba33fe1742c2d95a5d77a6278657a4bbd634c7b038a67c5299b93de180491cc17c13832365348a14cf2c8b035a415a761562cac4d1e12ffc331148b0806f673236cb6d18cd8d0858427b71d1abbe51bd2275eaf436540857f1f889856ef965d531b6baefe4302efe0d9c2d38c97debc8155bf8e4ba9964d0e94c1805b2fb74a98cb1a1bbd6b55380f336c59c707a173ed618aabbba9857f2a05310d30e23aafc367cc3bf89e19cd8cc92d4079536c799d69dda0f40f74bee9007b0b8d5132a4bfb9674bf0231fcac4618833f6d70366110101fc4d5ccc4ccb099c58c30a2e4af787c38148bd8e4fa91681030b84726cccc38e9cf90f9b3e048f06d03fc2f6e7bdfdb6c210b0b15bdd5b383fa1e29baef18b68d63486'}], 'fee': '23000000', 'id': '2db14633-6d02-477f-8483-abce65207c20', 'off': 'f0235999b19c740514147b79814e2e1fbfc08c8d78798b30d98cace7871d6d56', 'proof': {'raddr': '9ab530eba123fd4f6806d10550749c71b01933e7f755b932320db5b990472558', 'rsig': 'e02f542213953f89afdd7f67c4c6130a52fa6f8472a0bed7abf5c19a36cf45c14617fc35d9bf9d27a35840492d6117af43845cc606ba81e07966e755c9e75203', 'saddr': '9fa77f5c549c0ca1a78c7568f316861183e679b7cb953f220691fabb7ca984be'}, 'sigs': [{'nonce': '03849a7c2cc6a92a6c90fc412c190dd16dae5af85c8f9928c53ab0676aaabae71d', 'part': '1de7baaa6a67b03ac528998f5cf85aae6dd10d192c41fc906c2aa9c62c7c9a84aa49cf4cb64fb8c7c4cf94d088ea0a0bcb4b862d49cfd607aecd44813c33aab6', 'xs': '0283756cf28dab56dfccce28c91d141de97cea72f3c69934d5b3fb450df6d191eb'}, {'nonce': '02c0b58645da7f3187a79f1479f91b2b4290b7b36c52452b4e518f1b6c7683e0a9', 'part': 'a9e083766c1b8f514e2b45526cb3b790422b1bf979149fa787317fda4586b5c01eb283c3133c352cd139eed0f7fc66487244b15b1a5f0cb2041aad2a11eb14ff', 'xs': '0226a00de6a6e302596aab0317312b7b34ea6d4f974ee27a88b7506c23b0976118'}], 'sta': 'S3', 'ver': '4:3'}
    '''

    # test:  invalid api_sercet_file
    # test:  invalid api_user
    # test:  invalid api_password
    # test:  invalid wallet_password
    # test:  invalid params for each method
    #        ex:   wallet.retrieve_txs(tx_id="x")
