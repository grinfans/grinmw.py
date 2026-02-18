import unittest
import base64
import json
import os

from grinmw.wallet import encrypt, decrypt

def mocked_get(m, target_url, mocked_response, status_code=200):
    m.get(
        target_url,
        json=mocked_response,
        status_code=status_code)

def mock_post(
    m,                     # the requests_mock.Mocker instance
    target_url,
    mocked_response,
    expected_body=None,    # optional – dict to match against sent JSON
    status_code=200,
    expected_auth=None     # NEW: tuple (username, password) or None
):
    def matcher(request):
        ok = True
        # Optional: check body
        if expected_body is not None:
            try:
                ok = ok and (request.json() == expected_body)
            except:
                ok = False
        # Optional: check basic auth
        if expected_auth is not None:
            auth_header = request.headers.get('Authorization', '')
            # Basic auth header looks like: "Basic dXNlcjpwYXNz"
            try:
                decoded = base64.b64decode(auth_header.split(' ', 1)[1]).decode('utf-8')
                user, pw = decoded.split(':', 1)
                ok = ok and (user == expected_auth[0] and pw == expected_auth[1])
            except:
                ok = False
        return ok

    m.post(
        target_url,
        json=mocked_response,
        status_code=status_code,
        additional_matcher=matcher if (expected_body is not None or expected_auth is not None) else None
    )

def mock_post_key_exchange(
    m,
    target_url,
    mock_response_pubkey_hex,
    captured_pubkeys,
    expected_auth=('grin', 'password'),
    status_code=200
):
    def matcher_and_capture(request):
        ok = True

        if expected_auth:
            auth_header = request.headers.get('Authorization', '')
            try:
                decoded = base64.b64decode(auth_header.split(' ', 1)[1]).decode('utf-8')
                user, pw = decoded.split(':', 1)
                ok = ok and (user == expected_auth[0] and pw == expected_auth[1])
            except Exception as e:
                ok = False

        print(ok)
        if ok:
            try:
                body = request.json()
                pubkey_hex = body.get('params', {}).get('ecdh_pubkey', None)
                print(pubkey_hex)
                if pubkey_hex:
                    print('side_effect')
                    captured_pubkeys.append(pubkey_hex)
                else:
                    ok = False
            except Exception as e:
                print(e)
                ok = False

        print('final ok?', ok)
        return ok

    def response(request):
        return {
            'jsonrpc': '2.0',
            'id': 1,
            'result': {'Ok': mock_response_pubkey_hex}
        }

    m.post(
        target_url,
        json=response, # dynamic response
        status_code=status_code,
        additional_matcher=matcher_and_capture
    )

def mock_post_encrypted(
    m,                        # requests_mock.Mocker
    target_url: str,
    shared_secret: str,     # same secret client & mock use
    expected_decrypted_body: dict,   # what client should send after decrypt
    mocked_response_payload: dict,   # the real JSON-RPC result you want to return
    status_code: int = 200
):
    def custom_matcher(request):
        try:
            # Parse incoming JSON
            incoming = request.json()
            incoming_nonce_hex = incoming["params"]["nonce"]
            incoming_body_enc  = incoming["params"]["body_enc"]

            nonce_in = bytes.fromhex(incoming_nonce_hex)

            # Decrypt what client sent
            decrypted_str = decrypt(shared_secret, incoming_body_enc, nonce_in)
            decrypted_dict = json.loads(decrypted_str)

            # Assert / compare
            if decrypted_dict != expected_decrypted_body:
                return False   # or raise / log – for strict test fail

            return True

        except Exception as exc:
            # Wrong format / decryption fail → reject
            return False

    def response_callback(request, context):
        # Create fresh nonce for response
        resp_nonce = os.urandom(12)

        # Prepare inner JSON-RPC response
        inner_json = {
            "jsonrpc": "2.0",
            "id": expected_decrypted_body["id"],  # usually keep client's id
            "result": mocked_response_payload     # ← your mocked result here
        }
        inner_str = json.dumps(inner_json, separators=(",", ":"))

        # Encrypt response
        encrypted_resp = encrypt(shared_secret, inner_str, resp_nonce)

        # Format expected by client
        return {
            'result': {
                "Ok": {
                    "nonce": resp_nonce.hex(),
                    "body_enc": encrypted_resp
                }
            }
        }

    # Register the mock with matcher + dynamic response
    m.post(
        target_url,
        additional_matcher=custom_matcher,
        json=response_callback
    )

WalletConfig = {
    "owner_api_url": "http://localhost:3420/v3/owner",
    "owner_api_user": "grin",
    "owner_api_secret": "/home/bdoyle/.grin/main/.owner_api_secret",
    "seed_password": '123',  # Wallet Password
}

class GrinAPITestClass(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
