import requests_mock

from grinmw import WalletV2Foreign
from tests import GrinAPITestClass, mock_post


class TestForeignApiV2Methods(GrinAPITestClass):
    def test_check_version(self):
        with requests_mock.Mocker() as m:
            client_foreign = WalletV2Foreign(
                'http://localhost:3415/v2/foreign')

            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'check_version',
                'params': []
            }
            mocked_response_result = {
			    "foreign_api_version": 2,
			    "supported_slate_versions": [
				    "V4"
			    ]
		    }
            mocked_response = {
	            "id": 1,
	            "jsonrpc": "2.0",
	            "result": {
		            "Ok": mocked_response_result
	            }
            }

            mock_post(
                m,
                'http://localhost:3415/v2/foreign',
                mocked_response,
                expected_body=None,
                status_code=200)

            result = client_foreign.check_version()
            assert result == mocked_response_result

    def test_build_coinbase(self):
        with requests_mock.Mocker() as m:
            client_foreign = WalletV2Foreign(
                'http://localhost:3415/v2/foreign')

            fees = 0
            height = 0
            key_id = None
            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': '',
                'params': [
                    {
                        'fees': fees,
                        'height': height,
                        'key_id': key_id
                    }
                ]
            }
            mocked_response_result = {
			    "kernel": {
				    "excess": "08dfe86d732f2dd24bac36aa7502685221369514197c26d33fac03041d47e4b490",
				    "excess_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be02fa098c54c9bf638e0ee1ad5eb896caa11565f632be7b9cd65643ba371044f",
				    "features": "Coinbase"
			    },
			    "key_id": "0300000000000000000000000400000000",
			    "output": {
				    "commit": "08fe198e525a5937d0c5d01fa354394d2679be6df5d42064a0f7550c332fce3d9d",
				    "features": "Coinbase",
				    "proof": "9d8488fcb43c9c0f683b9ce62f3c8e047b71f2b4cd94b99a3c9a36aef3bb8361ee17b4489eb5f6d6507250532911acb76f18664604c2ca4215347a5d5d8e417d00ca2d59ec29371286986428b0ec1177fc2e416339ea8542eff8186550ad0d65ffac35d761c38819601d331fd427576e2fff823bbc3faa04f49f5332bd4de46cd4f83d0fd46cdb1dfb87069e95974e4a45e0235db71f5efe5cec83bbb30e152ac50a010ef4e57e33aabbeb894b9114f90bb5c3bb03b009014e358aa3914b1a208eb9d8806fbb679c256d4c1a47b0fce3f1235d58192cb7f615bd7c5dab48486db8962c2a594e69ff70029784a810b4eb76b0516805f3417308cda8acb38b9a3ea061568f0c97f5b46a3beff556dc7ebb58c774f08be472b4b6f603e5f8309c2d1f8d6f52667cb86816b330eca5374148aa898f5bbaf3f23a3ebcdc359ee1e14d73a65596c0ddf51f123234969ac8b557ba9dc53255dd6f5c0d3dd2c035a6d1a1185102612fdca474d018b9f9e81acfa3965d42769f5a303bbaabb78d17e0c026b8be0039c55ad1378c8316101b5206359f89fd1ee239115dde458749a040997be43c039055594cab76f602a0a1ee4f5322f3ab1157342404239adbf8b6786544cd67d9891c2689530e65f2a4b8e52d8551b92ffefb812ffa4a472a10701884151d1fb77d8cdc0b1868cb31b564e98e4c035e0eaa26203b882552c7b69deb0d8ec67cf28d5ec044554f8a91a6cae87eb377d6d906bba6ec94dda24ebfd372727f68334af798b11256d88e17cef7c4fed092128215f992e712ed128db2a9da2f5e8fadea9395bddd294a524dce47f818794c56b03e1253bf0fb9cb8beebc5742e4acf19c24824aa1d41996e839906e24be120a0bdf6800da599ec9ec3d1c4c11571c9f143eadbb554fa3c8c9777994a3f3421d454e4ec54c11b97eea3e4e6ede2d97a2bc"
			    }
		    }
            mocked_response = {
	            "id": 1,
	            "jsonrpc": "2.0",
	            "result": {
		            "Ok": mocked_response_result
	            }
            }

            mock_post(
                m,
                'http://localhost:3415/v2/foreign',
                mocked_response,
                expected_body=None,
                status_code=200)

            result = client_foreign.build_coinbase(
                fees, height, key_id=key_id)
            assert result == mocked_response_result

    def test_receive_tx(self):
        with requests_mock.Mocker() as m:
            client_foreign = WalletV2Foreign(
                'http://localhost:3415/v2/foreign')

            slate= {
			    "amt": "6000000000",
			    "fee": "23500000",
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "off": "d202964900000000d302964900000000d402964900000000d502964900000000",
			    "proof": {
				    "raddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3",
				    "saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
			    },
			    "sigs": [
				    {
					    "nonce": "02b57c1f4fea69a3ee070309cf8f06082022fe06f25a9be1851b56ef0fa18f25d6",
					    "xs": "023878ce845727f3a4ec76ca3f3db4b38a2d05d636b8c3632108b857fed63c96de"
				    }
			    ],
			    "sta": "S1",
			    "ver": "4:2"
		    }
            dest_acct_name = None
            r_addr = None
            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'receive_tx',
                'params': [
                    slate, dest_acct_name, r_addr
                ]
            }
            mocked_response_result = {
			    "coms": [
				    {
					    "c": "091582c92b99943b57955e52b5ccf1223780c2a2e55995c00c86fca2bcb46b6b9f",
					    "p": "49972a8d5b7c088e7813c3988ebe0982f8f0b12b849b1788df7da07b549408b0d6c99f80c0e2335370c104225ef5d282d79966e9044c959bedc3be03af6246fa07fc13eb3c60c90213c9f3a7a5ecf9a34c8fbaddc1a72e49e12dba9495e5aaa53bb6ac6ed63d8774707c57ab604d6bdc46de18da57a731fe336c3ccef92b4dae967417ffdae2c7d75864d46d30e287dd9cc15882e15f296b9bab0040e4432f4024be33924f112dd26c90cc800ac09a327b0ac3a661f63da9945fb1bcc82a7777d61d97cbe657675e22d035d2cf9ea03a89cfa410960ebc18a0a18b1909f4c5bef20b0fd13ffcf5a818ad8768d354b1c0f2e9b16dd7a9cf0641546f57d1945a98b8684d067dd085b90b40457e4c14665fb1b94feecf30a90f508ded16ba1bba8080a6866dffd0b1f01738fff8c62ce5e38e677835752a1b4072124dd9ff14ba8ff92126baebbb5f6e14fbb052f5d5b09aec11bfd880d7d4640a295aa83f184034d26f00cbdbabf9b89fddd7a7c9cc8c5d4b53fc39971e4495a8d984ac9607be89780fde528ee3f2d6b912908b4caf04f5c93f64431517af6b32d0b9c18255959f6903c6696ec71f615a0c877630a2d871f3f8a107fc80f306a94b6ad5790070f7d2535163bad7feae9263a9d3558ea1acecc4e61ff4e05b0162f6aba1a3b299ff1c3bb85e4109e550ad870c328bedc45fed8b504f679bc3c1a25b2b65ede44602f21fac123ba7c5f132e7c786bf9420a27bae4d2559cf7779e77f96b747b6d3ad5c13b5e8c9b49a7083001b2f98bcf242d4644537bb5a3b5b41764812a93395b7ab372c18be575e02c3763b4170234e5fddeb43420aadb71cb80f75cc681c1e7ffee3e6a8868c6076fd1da539ab9a12fef1c8cbe271b6de60100c9f82d826dc97b47b57ee9804e60112f556c1dce4f12ecc91ef34d69090b8c9d2ae9cbae38994a955cb"
				    }
			    ],
			    "id": "0436430c-2b02-624c-2032-570501212b00",
			    "off": "a4f88ac429dee1d453ae33ed9f944417a52c7310477936e484fd83f0f22db483",
			    "proof": {
				    "raddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3",
				    "rsig": "02357a13b304ba8e22f4896d5664b72ad6d1b824e88782e2b716686ea14ec47281ef5ee14c03ead84c3260f5b0c1529ad3ddae57f28f6b8b1b66532bfcb2ee0f",
				    "saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
			    },
			    "sigs": [
				    {
					    "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					    "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be4f81215c8e678c7bd5f04f3562388948864d7a5a0374e220ab6dc5e02bae66f",
					    "xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f"
				    }
			    ],
			    "sta": "S2",
			    "ver": "4:2"
		    }
            mocked_response = {
	            "id": 1,
	            "jsonrpc": "2.0",
	            "result": {
		            "Ok": mocked_response_result
	            }
            }

            mock_post(
                m,
                'http://localhost:3415/v2/foreign',
                mocked_response,
                expected_body=None,
                status_code=200)

            result = client_foreign.receive_tx(
                slate, dest_acct_name=dest_acct_name, r_addr=r_addr)
            assert result == mocked_response_result

    def test_finalize_tx(self):
        with requests_mock.Mocker() as m:
            client_foreign = WalletV2Foreign(
                'http://localhost:3415/v2/foreign')

            slate = {
		        "ver": "4:2",
		        "id": "0436430c-2b02-624c-2032-570501212b00",
		        "sta": "I2",
		        "off": "383bc9df0dd332629520a0a72f8dd7f0e97d579dccb4dbdc8592aa3d424c846c",
		        "fee": "23500000",
		        "sigs": [
			        {
				        "xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
				        "nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
				        "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be7bf31d80494f5e4a3d656649b1610c61a268f9cafcfc604b5d9f25efb2aa3c5"
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
				        "c": "09ede20409d5ae0d1c0d3f3d2c68038a384cdd6b7cc5ca2aab670f570adc2dffc3",
				        "p": "6d86fe00220f8c6ac2ad4e338d80063dba5423af525bd273ecfac8ef6b509192732a8cd0c53d3313e663ac5ccece3d589fd2634e29f96e82b99ca6f8b953645a005d1bc73493f8c41f84fb8e327d4cbe6711dba194a60db30700df94a41e1fda7afe0619169389f8d8ee12bddf736c4bc86cd5b1809a5a27f195209147dc38d0de6f6710ce9350f3b8e7e6820bfe5182e6e58f0b41b82b6ec6bb01ffe1d8b3c2368ebf1e31dfdb9e00f0bc68d9119a38d19c038c29c7b37e31246e7bba56019bc88881d7d695d32557fc0e93635b5f24deffefc787787144e5de7e86281e79934e7e20d9408c34317c778e6b218ee26d0a5e56b8b84a883e3ddf8603826010234531281486454f8c2cf3fee074f242f9fc1da3c6636b86fb6f941eb8b633d6e3b3f87dfe5ae261a40190bd4636f433bcdd5e3400255594e282c5396db8999d95be08a35be9a8f70fdb7cf5353b90584523daee6e27e208b2ca0e5758b8a24b974dca00bab162505a2aa4bcefd8320f111240b62f861261f0ce9b35979f9f92da7dd6989fe1f41ec46049fd514d9142ce23755f52ec7e64df2af33579e9b8356171b91bc96b875511bef6062dd59ef3fe2ddcc152147554405b12c7c5231513405eb062aa8fa093e3414a144c544d551c4f1f9bf5d5d2ff5b50a3f296c800907704bed8d8ee948c0855eff65ad44413af641cdc68a06a7c855be7ed7dd64d5f623bbc9645763d48774ba2258240a83f8f89ef84d21c65bcb75895ebca08b0090b40aafb7ddef039fcaf4bad2dbbac72336c4412c600e854d368ed775597c15d2e66775ab47024ce7e62fd31bf90b183149990c10b5b678501dbac1af8b2897b67d085d87cab7af4036cba3bdcfdcc7548d7710511045813c6818d859e192e03adc0d6a6b30c4cbac20a0d6f8719c7a9c3ad46d62eec464c4c44b58fca463fea3ce1fc51"
			        }
		        ]
	        }
            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'finalize_tx',
                'params': [slate]
            }
            mocked_response_result = {}
            mocked_response = {
	            "id": 1,
	            "jsonrpc": "2.0",
	            "result": {
		            "Ok": mocked_response_result
	            }
            }

            mock_post(
                m,
                'http://localhost:3415/v2/foreign',
                mocked_response,
                expected_body=None,
                status_code=200)

            result = client_foreign.finalize_tx(slate)
            assert result == mocked_response_result
