import os
import socket
import unittest
from urllib.parse import urlparse

# We are testing this module
from wallet_v3 import WalletV3

##
# Test Configuration
WalletConfig = {
        "owner_api_url": "http://localhost:3420/v3/owner",
        "owner_api_user": "grin",
        "owner_api_secret": open("/home/bdoyle/.grin/main/.owner_api_secret").read().strip(),
        "seed_password": '123',  # Wallet Password
    }
 
##
# Test Cases
class TestOwnerApiV3Methods(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_1_connect_to_wallet_owner_api(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        url = urlparse(WalletConfig["owner_api_url"])
        address, port = url.netloc.split(":")
        location = (address, int(port))
        result = s.connect_ex(location)
        s.close()
        self.assertEqual(0, result, "Failed to connect to nodes owner API at: {url}")

    def test_2_init_secure_api(self):
        api_url = WalletConfig["owner_api_url"]
        api_user = WalletConfig["owner_api_user"]
        api_secret = WalletConfig["owner_api_secret"]
        wallet = WalletV3(api_url, api_user, api_secret)
        shared_ecdh_key = wallet.init_secure_api()
        self.assertIsNotNone(shared_ecdh_key, "Expected shared_ecdh_key")
        return wallet

    def test_3_open_wallet(self):
        wallet_password = WalletConfig["seed_password"]
        wallet = self.test_2_init_secure_api()
        token = wallet.open_wallet(None, wallet_password)
        self.assertIsNotNone(token, "Expected token")
        return wallet
        
    def test_4_node_height(self):
        wallet = self.test_3_open_wallet()
        result = wallet.node_height()
        self.assertTrue(result["updated_from_node"], "Expected wallet to be updated_from_node")
        self.assertGreater(int(result["height"]), 0)

    def test_m_get_mnemonic(self):
        wallet_password = WalletConfig["seed_password"]
        wallet = self.test_3_open_wallet()
        result = wallet.get_mnemonic(wallet_password)
        self.assertIsNotNone(result, "Expected mnemonic string")
        self.assertIsInstance(result, str, "Expected mnemonic string")
        self.assertGreater(len(result), 50, "mnemonic string appears too short")

    def test_m_get_slatepack_address(self):
        wallet = self.test_3_open_wallet()
        result = wallet.get_slatepack_address()
        self.assertIsNotNone(result, "Expected slatepack address string")
        self.assertIsInstance(result, str, "Expected slatepack string")
        self.assertGreater(len(result), 50, "slatepack string appears too short")

    def test_m_get_slatepack_secret_key(self):
        wallet = self.test_3_open_wallet()
        result = wallet.get_slatepack_secret_key()
        self.assertIsNotNone(result, "Expected slatepack secret key string")
        self.assertIsInstance(result, str, "Expected secret key string")
        self.assertGreater(len(result), 50, "slatepack secret key string appears too short")

    def test_m_get_top_level_directory(self):
        wallet = self.test_3_open_wallet()
        result = wallet.get_top_level_directory()
        self.assertIsNotNone(result, "Expected filesystem path string")
        self.assertIsInstance(result, str, "Expected failsystem path key string")
        exists = os.path.isdir(result)
        self.assertTrue(exists, "top_level_directory does not exist {result}")


if __name__ == '__main__':
    try:
        # Initial SetUp - provide a clean directory for wallet testing
        # XXX TODO
        # Currently this test requires an existing wallet

        # Run the tests
        unittest.main()

    finally:
        # Final TearDown - remove wallet testing directory
        # XXX TODO
        # Currently this test requires an existing wallet
        pass
