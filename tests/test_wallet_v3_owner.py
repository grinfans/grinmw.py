import os
import socket
import requests_mock

from ecies.utils import generate_key

from urllib.parse import urlparse

from grinmw import WalletV3Owner
from tests import GrinAPITestClass, WalletConfig, mock_post, mock_post_key_exchange, mock_post_encrypted


class TestOwnerApiV3Methods(GrinAPITestClass):
    def setUp(self):
        self.key = generate_key()
        self.pubkey = self.key.public_key.format().hex()

    def tearDown(self):
        del self.pubkey
        del self.key

    def util_mock_key_exchange(self, m, client_owner):
        mock_post(
            m,
            'http://localhost:3420/v3/owner',
            {'result': {'Ok': self.pubkey}},
            expected_body=None,
            status_code=200,
            expected_auth=('grin', 'password'))
        shared_secret = client_owner.init_secure_api()
        return shared_secret

    def util_open_wallet(
            self,
            m,
            client_owner,
            shared_secret,
            token='d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868'):
        expected_decrypted_body = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'open_wallet',
            'params': {
                'name': 'name',
                'password': 'password'
            }
        }
        mocked_response_payload = {
		    'Ok': token
	    }
        mock_post_encrypted(
            m,
            'http://localhost:3420/v3/owner',
            shared_secret,
            expected_decrypted_body,
            mocked_response_payload,
            200)
        token = client_owner.open_wallet('name', 'password')
        return token

    def test_init_secure_api(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')
            shared_secret = self.util_mock_key_exchange(m, client_owner)
            assert shared_secret

    def test_open_wallet(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)
            assert token == 'd096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868'

    def test_node_height(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'node_height',
                'params': {
                    'token': 'd096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868'
                }
            }
            expected_node_height = {
                'header_hash': 'd4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d',
                'height': '5',
                'updated_from_node': True
            }
            mocked_response_payload = {
                'Ok': expected_node_height
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            node_height = client_owner.node_height()
            assert node_height == expected_node_height

    def test_retrieve_txs(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'retrieve_txs',
                'params': {
                    'token': token,
                    'refresh_from_node': True,
                    'tx_id': None,
                    'tx_slate_id': None,
                }
            }
            expected_retrieve_tx = [
                True,
                [
                    {
		                "amount_credited": "60000000000",
		                "amount_debited": "0",
		                "confirmation_ts": "2019-01-15T16:01:26Z",
		                "confirmed": True,
		                "creation_ts": "2019-01-15T16:01:26Z",
		                "fee": None,
		                "id": 0,
		                "kernel_excess": "0838e19c490038b10f051c9c190a9b1f96d59bbd242f5d3143f50630deb74342ed",
		                "kernel_lookup_min_height": 1,
		                "num_inputs": 0,
		                "num_outputs": 1,
		                "parent_key_id": "0200000000000000000000000000000000",
		                "stored_tx": None,
		                "ttl_cutoff_height": None,
		                "tx_slate_id": None,
		                "payment_proof": None,
		                "reverted_after": None,
		                "tx_type": "ConfirmedCoinbase"
		            },
		            {
		                "amount_credited": "60000000000",
		                "amount_debited": "0",
		                "confirmation_ts": "2019-01-15T16:01:26Z",
		                "confirmed": True,
		                "creation_ts": "2019-01-15T16:01:26Z",
		                "fee": None,
		                "id": 1,
		                "kernel_excess": "08cd9d890c0b6a004f700aa5939a1ce0488fe2a11fa33cf096b50732ceab0be1df",
		                "kernel_lookup_min_height": 2,
		                "num_inputs": 0,
		                "num_outputs": 1,
		                "parent_key_id": "0200000000000000000000000000000000",
		                "stored_tx": None,
		                "ttl_cutoff_height": None,
		                "payment_proof": None,
		                "reverted_after": None,
		                "tx_slate_id": None,
		                "tx_type": "ConfirmedCoinbase"
		            }
                ]
            ]
            mocked_response_payload = {
                'Ok': expected_retrieve_tx
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.retrieve_txs()
            assert retrieve_tx == expected_retrieve_tx[1]

    def test_retrieve_outputs(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'retrieve_outputs',
                'params': {
                    'token': token,
                    'include_spent': False,
                    'refresh_from_node': True,
                    'tx_id': None,
                }
            }

            expected_result = [
                True,
				[
                    {
					    "commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
					    "output": {
						    "commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
						    "height": "1",
						    "is_coinbase": True,
						    "key_id": "0300000000000000000000000000000000",
						    "lock_height": "4",
						    "mmr_index": None,
						    "n_child": 0,
						    "root_key_id": "0200000000000000000000000000000000",
						    "status": "Unspent",
						    "tx_log_entry": 0,
						    "value": "60000000000"
					    }
				    },
				    {
					    "commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
					    "output": {
						    "commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
						    "height": "2",
						    "is_coinbase": True,
						    "key_id": "0300000000000000000000000100000000",
						    "lock_height": "5",
						    "mmr_index": None,
						    "n_child": 1,
						    "root_key_id": "0200000000000000000000000000000000",
						    "status": "Unspent",
						    "tx_log_entry": 1,
						    "value": "60000000000"
					    }
				    }
                ]
			]


            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.retrieve_outputs(
                include_spent=False, tx_id=None, refresh=True)
            assert retrieve_tx == expected_result[1]

    def test_retrieve_summary_info(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'retrieve_summary_info',
                'params': {
                    'token': token,
                    'minimum_confirmations': 1,
                    'refresh_from_node': True,
                }
            }

            expected_result = [
			    True,
			    {
				    "amount_awaiting_confirmation": "0",
				    "amount_awaiting_finalization": "0",
				    "amount_currently_spendable": "60000000000",
				    "amount_immature": "180000000000",
				    "amount_locked": "0",
				    "amount_reverted": "0",
				    "last_confirmed_height": "4",
				    "minimum_confirmations": "1",
				    "total": "240000000000"
			    }
		    ]

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.retrieve_summary_info(minimum_confirmations=1, refresh=True)
            assert retrieve_tx == expected_result[1]

    def test_cancel_tx(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'cancel_tx',
                'params': {
                    'token': token,
                    'tx_id': None,
                    'tx_slate_id': '0436430c-2b02-624c-2032-570501212b00',
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.cancel_tx(tx_slate_id='0436430c-2b02-624c-2032-570501212b00')
            assert retrieve_tx == expected_result

    def test_scan(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'scan',
                'params': {
                    'token': token,
                    'start_height': 1,
                    'delete_unconfirmed': False,
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.scan(start_height=1, delete_unconfirmed=False)
            assert retrieve_tx == expected_result

    def test_finalize_tx(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            slate = {
			    "ver": "4:2",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "sta": "S2",
			    "off": "6c6a69136154775488782121887bb3c32787a8320551fdb9732ec2d333fe54ee",
			    "sigs": [
				    {
					    "xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					    "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be7bf31d80494f5e4a3d656649b1610c61a268f9cafcfc604b5d9f25efb2aa3c5"
				    }
			    ],
			    "coms": [
				    {
					    "c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
					    "p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
				    }
			    ]
		    }

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'finalize_tx',
                'params': {
                    'token': token,
                    'slate': slate
                }
            }

            expected_result = {
			    "coms": [
				    {
					    "c": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
					    "f": 1
				    },
				    {
					    "c": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
					    "f": 1
				    },
				    {
					    "c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
					    "p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
				    },
				    {
					    "c": "09ede20409d5ae0d1c0d3f3d2c68038a384cdd6b7cc5ca2aab670f570adc2dffc3",
					    "p": "6d86fe00220f8c6ac2ad4e338d80063dba5423af525bd273ecfac8ef6b509192732a8cd0c53d3313e663ac5ccece3d589fd2634e29f96e82b99ca6f8b953645a005d1bc73493f8c41f84fb8e327d4cbe6711dba194a60db30700df94a41e1fda7afe0619169389f8d8ee12bddf736c4bc86cd5b1809a5a27f195209147dc38d0de6f6710ce9350f3b8e7e6820bfe5182e6e58f0b41b82b6ec6bb01ffe1d8b3c2368ebf1e31dfdb9e00f0bc68d9119a38d19c038c29c7b37e31246e7bba56019bc88881d7d695d32557fc0e93635b5f24deffefc787787144e5de7e86281e79934e7e20d9408c34317c778e6b218ee26d0a5e56b8b84a883e3ddf8603826010234531281486454f8c2cf3fee074f242f9fc1da3c6636b86fb6f941eb8b633d6e3b3f87dfe5ae261a40190bd4636f433bcdd5e3400255594e282c5396db8999d95be08a35be9a8f70fdb7cf5353b90584523daee6e27e208b2ca0e5758b8a24b974dca00bab162505a2aa4bcefd8320f111240b62f861261f0ce9b35979f9f92da7dd6989fe1f41ec46049fd514d9142ce23755f52ec7e64df2af33579e9b8356171b91bc96b875511bef6062dd59ef3fe2ddcc152147554405b12c7c5231513405eb062aa8fa093e3414a144c544d551c4f1f9bf5d5d2ff5b50a3f296c800907704bed8d8ee948c0855eff65ad44413af641cdc68a06a7c855be7ed7dd64d5f623bbc9645763d48774ba2258240a83f8f89ef84d21c65bcb75895ebca08b0090b40aafb7ddef039fcaf4bad2dbbac72336c4412c600e854d368ed775597c15d2e66775ab47024ce7e62fd31bf90b183149990c10b5b678501dbac1af8b2897b67d085d87cab7af4036cba3bdcfdcc7548d7710511045813c6818d859e192e03adc0d6a6b30c4cbac20a0d6f8719c7a9c3ad46d62eec464c4c44b58fca463fea3ce1fc51"
				    }
			    ],
			    "fee": "23500000",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "off": "a5a632f26f27a9b71e98c1c8b8098bb41204ffcfd206d995f9c16d10764ad95a",
			    "sigs": [
				    {
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					    "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be7bf31d80494f5e4a3d656649b1610c61a268f9cafcfc604b5d9f25efb2aa3c5",
					    "xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f"
				    },
				    {
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					    "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b04e1e15ceb1b5dbab8baf7750d7bd4aad6cfe97b83e4dc080dae328eb75881fd",
					    "xs": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec"
				    }
			    ],
			    "sta": "S3",
			    "ver": "4:2"
		    }

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.finalize_tx(slate)
            assert retrieve_tx == expected_result

    def test_get_stored_tx(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_stored_tx',
                'params': {
                    'token': token,
                    'id': None,
                    'slate_id': '0436430c-2b02-624c-2032-570501212b00',
                }
            }

            expected_result = {
			    "coms": [
				    {
					    "c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
					    "p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
				    }
			    ],
			    "fee": "23500000",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "sigs": [],
			    "sta": "S3",
			    "ver": "4:3"
		    }

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.get_stored_tx(
                id=None, slate_id='0436430c-2b02-624c-2032-570501212b00')
            assert retrieve_tx == expected_result

    def test_init_send_tx(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            args = {
				"src_acct_name": None,
				"amount": "6000000000",
				"minimum_confirmations": 2,
				"max_outputs": 500,
				"num_change_outputs": 1,
				"selection_strategy_is_use_all": True,
				"target_slate_version": None,
				"payment_proof_recipient_address": "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp",
				"ttl_blocks": None,
				"send_args": None
			}
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'init_send_tx',
                'params': {
                    'token': token,
                    'args': args
                }
            }

            expected_result = {
				"amt": "6000000000",
				"fee": "23000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"proof": {
					"raddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3",
					"saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
				},
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"xs": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec"
					}
				],
				"sta": "S1",
				"ver": "4:2"
			}

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.init_send_tx(args)
            assert retrieve_tx == expected_result

    def test_issue_invoice_tx(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            args = {
				"amount": "6000000000",
				"dest_acct_name": None,
				"target_slate_version": None
			}
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'issue_invoice_tx',
                'params': {
                    'token': token,
                    'args': args
                }
            }

            expected_result = {
				"amt": "6000000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"xs": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec"
					}
				],
				"sta": "I1",
				"ver": "4:2"
			}

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.issue_invoice_tx(args)
            assert retrieve_tx == expected_result

    def test_post_tx(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            slate = {
			    "ver": "4:2",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "sta": "S3",
			    "off": "750dbf4fd43b7f4cfd68d2698a522f3ff6e6a00ad9895b33f1ec46493b837b49",
			    "fee": "23500000",
			    "sigs": [
				    {
					    "xs": "033bbe2a419ea2e9d6810a8d66552e709d1783ca50759a44dbaf63fc79c0164c4c",
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					    "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b92c7c53280dd79f8b028cd9863bac89820267cac794b121e217541efb061ad53"
				    },
				    {
					    "xs": "02b57c1f4fea69a3ee070309cf8f06082022fe06f25a9be1851b56ef0fa18f25d6",
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					    "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b4cd4afef1cd2d708100cd1680d6566e4e987ac5c939ace9c0e036a679121c7a8"
				    }
			    ],
			    "coms": [
				    {
					    "f": 1,
					    "c": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045"
				    },
				    {
					    "f": 1,
					    "c": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7"
				    },
				    {
					    "c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
					    "p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
				    },
				    {
					    "c": "09ede20409d5ae0d1c0d3f3d2c68038a384cdd6b7cc5ca2aab670f570adc2dffc3",
					    "p": "6d86fe00220f8c6ac2ad4e338d80063dba5423af525bd273ecfac8ef6b509192732a8cd0c53d3313e663ac5ccece3d589fd2634e29f96e82b99ca6f8b953645a005d1bc73493f8c41f84fb8e327d4cbe6711dba194a60db30700df94a41e1fda7afe0619169389f8d8ee12bddf736c4bc86cd5b1809a5a27f195209147dc38d0de6f6710ce9350f3b8e7e6820bfe5182e6e58f0b41b82b6ec6bb01ffe1d8b3c2368ebf1e31dfdb9e00f0bc68d9119a38d19c038c29c7b37e31246e7bba56019bc88881d7d695d32557fc0e93635b5f24deffefc787787144e5de7e86281e79934e7e20d9408c34317c778e6b218ee26d0a5e56b8b84a883e3ddf8603826010234531281486454f8c2cf3fee074f242f9fc1da3c6636b86fb6f941eb8b633d6e3b3f87dfe5ae261a40190bd4636f433bcdd5e3400255594e282c5396db8999d95be08a35be9a8f70fdb7cf5353b90584523daee6e27e208b2ca0e5758b8a24b974dca00bab162505a2aa4bcefd8320f111240b62f861261f0ce9b35979f9f92da7dd6989fe1f41ec46049fd514d9142ce23755f52ec7e64df2af33579e9b8356171b91bc96b875511bef6062dd59ef3fe2ddcc152147554405b12c7c5231513405eb062aa8fa093e3414a144c544d551c4f1f9bf5d5d2ff5b50a3f296c800907704bed8d8ee948c0855eff65ad44413af641cdc68a06a7c855be7ed7dd64d5f623bbc9645763d48774ba2258240a83f8f89ef84d21c65bcb75895ebca08b0090b40aafb7ddef039fcaf4bad2dbbac72336c4412c600e854d368ed775597c15d2e66775ab47024ce7e62fd31bf90b183149990c10b5b678501dbac1af8b2897b67d085d87cab7af4036cba3bdcfdcc7548d7710511045813c6818d859e192e03adc0d6a6b30c4cbac20a0d6f8719c7a9c3ad46d62eec464c4c44b58fca463fea3ce1fc51"
				    }
			    ]
		    }
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'post_tx',
                'params': {
                    'token': token,
                    'slate': slate,
                    'fluff': False
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.post_tx(slate, fluff=False)
            assert retrieve_tx == expected_result

    def test_process_invoice_tx(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            slate = {
				"amt": "6000000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"xs": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40"
					}
				],
				"sta": "I1",
				"ver": "4:2"
			}
            args = {
				"src_acct_name": None,
				"amount": "0",
				"minimum_confirmations": 2,
				"max_outputs": 500,
				"num_change_outputs": 1,
				"selection_strategy_is_use_all": True,
				"target_slate_version": None,
				"payment_proof_recipient_address": None,
				"ttl_blocks": None,
				"send_args": None
			}
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'process_invoice_tx',
                'params': {
                    'token': token,
                    'slate': slate,
                    'args': args
                }
            }

            expected_result = {
			    "coms": [
				    {
					    "c": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
					    "f": 1
				    },
				    {
					    "c": "087e4e373ef2ab9921ba53e05f384b717789ddb4ad18a8f2057c9338bd639e02a5",
					    "p": "28875d797af7cb6c63eba070e0a79af57ea0a434d7d34801a02bc85624ae14a4a13519164737c7154b6222a9d6da33b8c52ef7dc4dc58aea3c776b7907e474450a52f3ccc017f66e2ce9f97a45733d6ed90a223e7d1a67802d393834cc9e4103c27bb7d63abc2753a5b54bcc48751c63b6accde16a37678338452bc985d24fb6af405a9166c0ca750f1cdedc5c0996c56f199722df3844b822de96480fac6e706dab6241d0338d7914a10a0e83406d0689224a3286e8c579c50882ce96123aecc6aa667c27abf1ce894e0c6282fc81e5fba51d498af16c5b0c39b45faf3f0cd7140dccae7d8d45330ec7895ce0c90e2490877311b9dfe157c05c6206f929ffef0da1a8d807077712a80670dfb9ac38ca565d47acf7e93bd09f418f20f10c9e87f6f4421fa889e522c33475f98ddff87a36eb0a0b445a8679628e163ae56bf3cfc39a5a5867d3e31e1e9d373a6b3924d7d895d5140e4bf00c0cbf7f343c12dc2b2c6b01769a588cc1ef1178fbf3bd645e25bf5c458c4af79884329b7ed80e08868121baeb39b11814f2dd8dddbb7114382e65378e2c6f1e837ace9a980acb965629f9f1525f60efb54301a7540a9105bf33eac1be37e1add96801f1c62857be0ac38ac370e0722764c59517960056bafe6fdd388eb78c98954f3f966d44e8f060366617844eff416625f8609b44263efc10e4f2f4fb22ceae5c16d4105e477a49511b4ac37aefac17e5532ee1ccb1654eb0bf17b32415561f02c2b07462f2c5aa7846ef21cfb30548c6bfe4d762333a199be183d7d9fa1ae6c9b4730965f741183d75ac0610efcf48d0039514011816f421a7a1a4c7c1bbc2ba8b522178cff367b4c704d343fac3a2662b50211556b630b5620244587d2f90941ef1edf8e44fa97d35daaa58d16fff3f57c6e6fa618f511dc770704d831a1f49630ec9da6f33f551923c"
				    }
			    ],
			    "fee": "23000000",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "off": "16672e6b4e2a6851b27641d8b5c32fcee83abbd516ceb9af5f0e8b6aad8d26a5",
			    "sigs": [
				    {
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					    "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bdac2d36fe4c972de75f4e462004de9ca3e8c77d4dae5344d210beea9ad138c45",
					    "xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f"
				    }
			    ],
			    "sta": "I2",
			    "ver": "4:2"
		    }

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.process_invoice_tx(slate, args)
            assert retrieve_tx == expected_result

    def test_tx_lock_outputs(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            slate = {
			    "ver": "4:2",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "sta": "S1",
			    "off": "d202964900000000d302964900000000d402964900000000d502964900000000",
			    "amt": "60000000000",
			    "fee": "7000000",
			    "sigs": [
				    {
					    "xs": "030152d2d72e2dba7c6086ad49a219d9ff0dfe0fd993dcaea22e058c210033ce93",
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				    }
			    ]
		    }
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'tx_lock_outputs',
                'params': {
                    'token': token,
                    'slate': slate
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.tx_lock_outputs(slate)
            assert retrieve_tx == expected_result

    def test_accounts(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'accounts',
                'params': {
                    'token': token
                }
            }

            expected_result = [
			    {
				    "label": "default",
				    "path": "0200000000000000000000000000000000"
			    }
		    ]

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.accounts()
            assert retrieve_tx == expected_result

    def test_change_password(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            old = 'passold'
            new = 'passnew'
            name = 'accountname'
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'change_password',
                'params': {
                    'name': name,
                    'old': old,
                    'new': new,
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.change_password(old, new, name)
            assert retrieve_tx == expected_result

    def test_close_wallet(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            name = None
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'close_wallet',
                'params': {
                    'name': name,
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.close_wallet(name=name)
            assert retrieve_tx == expected_result

    def test_create_account_path(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            label = 'account1'
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'create_account_path',
                'params': {
                    'token': token,
                    'label': label
                }
            }

            expected_result = '0200000001000000000000000000000000'

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.create_account_path(label)
            assert retrieve_tx == expected_result

    def test_create_config(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            chain_type = "Mainnet"
            wallet_config = {
			    "chain_type": None,
			    "api_listen_interface": "127.0.0.1",
			    "api_listen_port": 3415,
			    "owner_api_listen_port": 3420,
			    "api_secret_path": None,
			    "node_api_secret_path": None,
			    "check_node_api_http_addr": "http://127.0.0.1:3413",
			    "owner_api_include_foreign": False,
			    "data_file_dir": "/path/to/data/file/dir",
			    "no_commit_cache": None,
			    "tls_certificate_file": None,
			    "tls_certificate_key": None,
			    "dark_background_color_scheme": None,
			    "keybase_notify_ttl": None
		    }
            logging_config = {
			    "log_to_stdout": False,
			    "stdout_log_level": "Info",
			    "log_to_file": True,
			    "file_log_level": "Debug",
			    "log_file_path": "/path/to/log/file",
			    "log_file_append": True,
			    "log_max_size": None,
			    "log_max_files": None,
			    "tui_running": None
		    }
            tor_config = {
			    "use_tor_listener": True,
			    "socks_proxy_addr": "127.0.0.1:9050",
			    "send_config_dir": "."
		    }
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'create_config',
                'params': {
                    'chain_type': chain_type,
                    'wallet_config': wallet_config,
                    'logging_config': logging_config,
                    'tor_config': tor_config
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.create_config(
                chain_type=chain_type,
                wallet_config=wallet_config,
                logging_config=logging_config,
                tor_config=tor_config)
            assert retrieve_tx == expected_result

    def test_create_slatepack_message(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            slate = {
			    "ver": "4:2",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "sta": "S1",
			    "off": "d202964900000000d302964900000000d402964900000000d502964900000000",
			    "amt": "60000000000",
			    "fee": "7000000",
			    "sigs": [
				    {
					    "xs": "030152d2d72e2dba7c6086ad49a219d9ff0dfe0fd993dcaea22e058c210033ce93",
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				    }
			    ]
		    }
            recipients = []
            sender_index = 0
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'create_slatepack_message',
                'params': {
                    'token': token,
                    'slate': slate,
                    'recipients': recipients,
                    'sender_index': sender_index
                }
            }

            expected_result = '"BEGINSLATEPACK. xyfzdULuUuM5r3R kS68aywyCuYssPs Jf1JbvnBcK6NDDo ajiGAgh2SPx4t49 xtKuJE3BZCcSEue ksecMmbSoV2DQbX gGcmJniP9UadcmR N1KSc5FBhwAaUjy LXeYDP7EV7Cmsj4 pLaJdZTJTQbccUH 2zG8QTgoEiEWP5V T6rKst1TibmDAFm RRVHYDtskdYJb5G krqfpgN7RjvPfpm Z5ZFyz6ipAt5q9T 2HCjrTxkHdVi9js 22tr2Lx6iXT5vm8 JL6HhjwyFrSaEmN AjsBE8jgiaAABA6 GGZKwcXeXToMfRt nL9DeX1. ENDSLATEPACK."'

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.create_slatepack_message(
                slate, recipients, sender_index=sender_index)
            assert retrieve_tx == expected_result

    def test_delete_wallet(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            name = None
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'delete_wallet',
                'params': {
                    'name': name
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.delete_wallet(name=name)
            assert retrieve_tx == expected_result

    def test_get_mnemonic(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            password = ''
            name = None
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_mnemonic',
                'params': {
                    'password': password,
                    'name': name
                }
            }

            expected_result = 'fat twenty mean degree forget shell check candy immense awful flame next during february bulb bike sun wink theory day kiwi embrace peace lunch'

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.get_mnemonic(password, name=name)
            assert retrieve_tx == expected_result

    def test_get_slatepack_address(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            derivation_index = 0
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_slatepack_address',
                'params': {
                    'token': token,
                    'derivation_index': derivation_index
                }
            }

            expected_result = 'tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp'

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.get_slatepack_address(derivation_index=derivation_index)
            assert retrieve_tx == expected_result

    def test_get_slatepack_secret_key(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            derivation_index = 0
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_slatepack_secret_key',
                'params': {
                    'token': token,
                    'derivation_index': derivation_index
                }
            }

            expected_result = '86cca2aedea7989dfcca62e54477301d098bac260656d11373e314c099f0b26f'

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.get_slatepack_secret_key(derivation_index=derivation_index)
            assert retrieve_tx == expected_result

    def test_get_top_level_directory(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_top_level_directory',
                'params': {}
            }

            expected_result = '/doctest/dir'

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.get_top_level_directory()
            assert retrieve_tx == expected_result

    def test_get_updater_messages(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            count = 1
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_updater_messages',
                'params': {
                    'count': count
                }
            }

            expected_result = []

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.get_updater_messages(count=count)
            assert retrieve_tx == expected_result

    def test_retrieve_payment_proof(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            refresh_from_node = True
            tx_id = None
            tx_slate_id = '0436430c-2b02-624c-2032-570501212b00'
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'retrieve_payment_proof',
                'params': {
                    'token': token,
                    'refresh_from_node': refresh_from_node,
                    'tx_id': tx_id,
                    'tx_slate_id': tx_slate_id
                }
            }

            expected_result = {
			    "amount": "60000000000",
			    "excess": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af",
			    "recipient_address": "tgrin10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqq6t83r",
			    "recipient_sig": "02868f2d2b983981f8f98043701687a8531ed2de564ea3df48e9e7e0229ccbe8359efe506896df2efbe3528e977252c50e4a41ca3cc9896e7c5a30bbb1d33604",
			    "sender_address": "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp",
			    "sender_sig": "c511764f3f61ed3d1cbca9514df8bc6811fad5662b1cb0e0587b9c9e49db9f33183cce71af6cb24b507fabf525a2bc405c6e84e63a60334edff0b451ae5e6102"
		    }

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.retrieve_payment_proof(
                refresh_from_node=refresh_from_node, tx_id=tx_id, tx_slate_id=tx_slate_id)
            assert retrieve_tx == expected_result

    def test_set_active_account(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            label = 'default'
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'set_active_account',
                'params': {
                    'token': token,
                    'label': label
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.set_active_account(label=label)
            assert retrieve_tx == expected_result

    def test_set_top_level_directory(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            dir_ = '/home/wallet_user/my_wallet_dir'
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'set_top_level_directory',
                'params': {
                    'dir': dir_
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.set_top_level_directory(dir_)
            assert retrieve_tx == expected_result

    def test_set_tor_config(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            tor_config = {
			    "use_tor_listener": True,
			    "socks_proxy_addr": "127.0.0.1:59050",
			    "send_config_dir": "."
		    }
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'set_tor_config',
                'params': {
                    'tor_config': tor_config
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.set_tor_config(tor_config)
            assert retrieve_tx == expected_result

    def test_slate_from_slatepack_message(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            message = 'BEGINSLATEPACK. 8GQrdcwdLKJD28F 3a9siP7ZhZgAh7w BR2EiZHza5WMWmZ Cc8zBUemrrYRjhq j3VBwA8vYnvXXKU BDmQBN2yKgmR8mX UzvXHezfznA61d7 qFZYChhz94vd8Ew NEPLz7jmcVN2C3w wrfHbeiLubYozP2 uhLouFiYRrbe3fQ 4uhWGfT3sQYXScT dAeo29EaZJpfauh j8VL5jsxST2SPHq nzXFC2w9yYVjt7D ju7GSgHEp5aHz9R xstGbHjbsb4JQod kYLuELta1ohUwDD pvjhyJmsbLcsPei k5AQhZsJ8RJGBtY bou6cU7tZeFJvor 4LB9CBfFB3pmVWD vSLd5RPS75dcnHP nbXD8mSDZ8hJS2Q A9wgvppWzuWztJ2 dLUU8f9tLJgsRBw YZAs71HiVeg7. ENDSLATEPACK.'
            secret_indices = [0]
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'slate_from_slatepack_message',
                'params': {
                    'token': token,
                    'message': message,
                    'secret_indices': secret_indices
                }
            }

            expected_result = {
			    "amt": "6000000000",
			    "fee": "8000000",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "off": "d202964900000000d302964900000000d402964900000000d502964900000000",
			    "proof": {
				    "raddr": "783f6528669742a990e0faf0a5fca5d5b3330e37bbb9cd5c628696d03ce4e810",
				    "saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
			    },
			    "sigs": [
				    {
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					    "xs": "023878ce845727f3a4ec76ca3f3db4b38a2d05d636b8c3632108b857fed63c96de"
				    }
			    ],
			    "sta": "S1",
			    "ver": "4:2"
		    }

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.slate_from_slatepack_message(message, secret_indices)
            assert retrieve_tx == expected_result

    def test_start_updater(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            frequency = 30000
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'start_updater',
                'params': {
                    'token': token,
                    'frequency': frequency
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.start_updater(frequency)
            assert retrieve_tx == expected_result

    def test_stop_updater(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'stop_updater',
                'params': {}
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.stop_updater()
            assert retrieve_tx == expected_result

    def test_verify_payment_proof(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            proof = {
			    "amount": "60000000000",
			    "excess": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af",
			    "recipient_address": "slatepack10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqnlumr7",
			    "recipient_sig": "02868f2d2b983981f8f98043701687a8531ed2de564ea3df48e9e7e0229ccbe8359efe506896df2efbe3528e977252c50e4a41ca3cc9896e7c5a30bbb1d33604",
			    "sender_address": "slatepack1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfskdvkdu",
			    "sender_sig": "c511764f3f61ed3d1cbca9514df8bc6811fad5662b1cb0e0587b9c9e49db9f33183cce71af6cb24b507fabf525a2bc405c6e84e63a60334edff0b451ae5e6102"
		    }
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'verify_payment_proof',
                'params': {
                    'token': token,
                    'proof': proof
                }
            }

            expected_result = {}

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.verify_payment_proof(proof)
            assert retrieve_tx == expected_result

    def test_create_wallet(self):
        with requests_mock.Mocker() as m:
            client_owner = WalletV3Owner(
                'http://localhost:3420/v3/owner',
                'grin',
                'password')

            shared_secret = self.util_mock_key_exchange(m, client_owner)
            token = self.util_open_wallet(m, client_owner, shared_secret)

            password = 'my_secret_password'
            name = None
            mnemonic = None
            mnemonic_length = 32
            expected_decrypted_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'create_wallet',
                'params': {
                    'password': password,
                    'name': name,
                    'mnemonic': mnemonic,
                    'mnemonic_length': mnemonic_length
                }
            }

            expected_result = None

            mocked_response_payload = {
                'Ok': expected_result
            }
            mock_post_encrypted(
                m,
                'http://localhost:3420/v3/owner',
                shared_secret,
                expected_decrypted_body,
                mocked_response_payload,
                200)
            retrieve_tx = client_owner.create_wallet(
                password, name=name, mnemonic=mnemonic, mnemonic_length=mnemonic_length)
            assert retrieve_tx == expected_result
