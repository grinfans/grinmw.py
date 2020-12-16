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
        return requests.post(
                self.api_url, json=payload, 
                auth=(self.api_user, self.api_password)).json()

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
        return json.loads(decrypt(self.share_secret, encrypted2, nonce2))

    def init_secure_api(self):
        pubkey = self.key.public_key.format().hex()
        resp = self.post('init_secure_api', {'ecdh_pubkey': pubkey})
        remote_pubkey = resp['result']['Ok']
        self.share_secret = PublicKey(bytes.fromhex(remote_pubkey)).multiply(self.key.secret).format().hex()[2:]

    def open_wallet(self, name, password):
        resp = self.post_encrypted('open_wallet',{
            'name': name,
            'password': password   
        })
        self.token = resp['result']['Ok']

    def get_height(self):
        resp = self.post_encrypted('node_height',
            {'token': self.token}
        )
        return resp

    def get_txs(self, tx_id, tx_slate_id):
        resp = self.post_encrypted('retrieve_txs',{
                'token': self.token,
                'refresh_from_node': True,
                'tx_id': tx_id,
                'tx_slate_id': tx_slate_id
        })
        return resp

    def get_outputs(self, include_spent, tx_id):
        resp = self.post_encrypted('retrieve_outputs',{
                'token': self.token,
                'include_spent': include_spent,
                'refresh_from_node': True,
                'tx_id': tx_id,
        })
        return resp

if __name__ == '__main__':
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
    print(wallet.get_outputs(False, None))