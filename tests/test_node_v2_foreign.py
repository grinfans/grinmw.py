import requests_mock

from grinmw import NodeV2Foreign
from tests import GrinAPITestClass, mock_post


class TestForeignApiV2Methods(GrinAPITestClass):
    def test_get_block(self):
        with requests_mock.Mocker() as m:
            node_url = 'http://localhost:3413/v2/foreign'
            node_user = 'grin'
            node_password = 'password'
            client_foreign = NodeV2Foreign(
                node_url, node_user, node_password)

            height = 374274
            hash_ = None
            commit = None
            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_block',
                'params': [height, hash_, commit]
            }
            mocked_response_result = {
		        "header": {
			        "cuckoo_solution": [
			            1263501, 14648727, 42430559, 58137254, 68666726, 72784903,
			            101936839, 104273571, 123886748, 131179768, 155443226, 162493783,
			            164784425, 167313215, 169806918, 183041591, 184403611, 210351649,
			            215159650, 239995384, 240935454, 257742462, 280820644, 300143903,
			            303146496, 311804841, 341039986, 354918290, 363508555, 377618528,
			            396693709, 397417856, 399875872, 413238540, 413767813, 432697194,
			            436903767, 447257325, 453337210, 459401597, 496068509, 511300624
			        ],
			        "edge_bits": 29,
			        "hash": "000001e16cb374e38c979c353a0aaffbf5b939da7688f69ad99efda6c112ea9b",
			        "height": 374274,
			        "kernel_root": "e17920c0e456a6feebf19e24a46f510a85f21cb60e81012f843c00fe2c4cad6e",
			        "nonce": 4354431877761457166,
			        "output_root": "1e9daee31b80c6b83573eacfd3048a4af57c614bd36f9acd5fb50fbd236beb16",
			        "prev_root": "9827b8ffab942e264b6ac81f2b487e3de65e411145c514092ce783df9344fa8a",
			        "previous": "00001266a73ba6a8032ef8b4d4f5508407ffb1c270c105dac06f4669c17af020",
			        "range_proof_root": "3491b8c46a3919df637a636ca72824377f89c4967dcfe4857379a4a82b510069",
			        "secondary_scaling": 571,
			        "timestamp": "2019-10-03T15:15:35+00:00",
			        "total_difficulty": 1133438031814173,
			        "total_kernel_offset": "63315ca0be65c9f6ddf2d3306876caf9f458a01d1a0bf50cc4d3c9b699161958",
			        "version": 2
		        },
		        "inputs": [],
		        "kernels": [
			        {
			            "excess": "08761e9cb1eea5bfcf771d1218b5ec802798d6eecaf75faae50ba3a1997aaef009",
			            "excess_sig": "971317046c533d21dff3e449cc9380c2be10b0274f70e009aa2453f755239e3299883c09a1785b15a141d89d563cdd59395886c7d63aba9c2b6438575555e2c4",
			            "features": "Coinbase",
			            "fee": 0,
			            "lock_height": 0
			        }
		        ],
		        "outputs": [
			        {
			            "block_height": 374274,
			            "commit": "09d33615563ba2d65acc2b295a024337166b9f520122d49730c73e8bfb43017610",
			            "merkle_proof": None,
			            "mmr_index": 4091742,
			            "output_type": "Coinbase",
			            "proof": "7adae7bcecf735c70eaa21e8fdce1d3c83d7b593f082fc29e16ff2c64ee5aaa15b682e5583257cf351de457dda8f877f4d8c1492af3aaf25cf5f496fce7ca54a0ef78cc61c4252c490386f3c69132960e9edc811add6415a6026d53d604414a5f4dd330a63fcbb005ba908a45b2fb1950a9529f793405832e57c89a36d3920715bc2d43db16a718ecd19aeb23428b5d3eeb89d73c28272a7f2b39b8923e777d8eb2c5ce9872353ba026dc79fdb093a6538868b4d184215afc29a9f90548f9c32aa663f9197fea1cadbb28d40d35ed79947b4b2b722e30e877a15aa2ecf95896faad173af2e2795b36ce342dfdacf13a2f4f273ab9927371f52913367d1d58246a0c35c8f0d2330fcddb9eec34c277b1cfdaf7639eec2095930b2adef17e0eb94f32e071bf1c607d2ef1757d66647477335188e5afc058c07fe0440a67804fbdd5d35d850391ead3e9c8a3136ae1c42a33d5b01fb2c6ec84a465df3f74358cbc28542036ae4ef3e63046fbd2bce6b12f829ed193fb51ea87790e88f1ea686d943c46714b076fb8c6be7c577bca5b2792e63d5f7b8f6018730b6f9ddaf5758a5fa6a3859d68b317ad4383719211e78f2ca832fd34c6a222a8488e40519179209ad1979f3095b7b7ba7f57e81c371989a4ace465149b0fe576d89473bc596c54cee663fbf78196e7eb31e4d56604c5226e9242a68bda95e1b45473c52f63fe865901839e82079a9935e25fe8d44e339484ba0a62d20857c6b3f15ab5c56b59c7523b63f86fa8977e3f4c35dc8b1c446c48a28947f9d9bd9992763404bcba95f94b45d643f07bb7c352bfad30809c741938b103a44218696206ca1e18f0b10b222d8685cc1ed89d5fdb0c7258b66486e35c0fd560a678864fd64c642b2b689a0c46d1be6b402265b7808cd61a95c2b4a4df280e3f0ec090197fb039d32538d05d3f0a082f5",
			            "proof_hash": "cfd97db403c274220bb0dbaf3ecc88e483c0b707d8e6f16dfda37cd4f2c3211c",
			            "spent": False
			        }
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
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password))

            result = client_foreign.get_block(height, hash_, commit)
            assert result == mocked_response_result

    def test_get_header(self):
        with requests_mock.Mocker() as m:
            node_url = 'http://localhost:3413/v2/foreign'
            node_user = 'grin'
            node_password = 'password'
            client_foreign = NodeV2Foreign(
                node_url, node_user, node_password)

            height=None
            hash_='00000100c54dcb7a9cbb03aaf55da511aca2c98b801ffd45046b3991e4f697f9'
            commit=None
            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_header',
                'params': [height, hash_, commit]
            }
            mocked_response_result = {
		        "cuckoo_solution": [
	                9886309, 35936712, 43170402, 48069549, 70022151, 97464262,
			        107044653, 108342481, 118947913, 130828808, 144192311, 149269998,
			        179888206, 180736988, 207416734, 227431174, 238941623, 245603454,
			        261819503, 280895459, 284655965, 293675096, 297070583, 299129598,
			        302141405, 313482158, 321703003, 351704938, 376529742, 381955038,
			        383597880, 408364901, 423241240, 436882285, 442043438, 446377997,
			        470779425, 473427731, 477149621, 483204863, 496335498, 534567776
		        ],
		        "edge_bits": 29,
		        "hash": "00000100c54dcb7a9cbb03aaf55da511aca2c98b801ffd45046b3991e4f697f9",
		        "height": 374336,
		        "kernel_mmr_size": 2210914,
		        "kernel_root": "d294e6017b9905b288dc62f6f725c864665391c41da20a18a371e3492c448b88",
		        "nonce": 4715085839955132421,
		        "output_mmr_size": 4092001,
		        "output_root": "12464313f7cd758a7761f65b2837e9b9af62ad4060c97180555bfc7e7e5808fa",
		        "prev_root": "e22090fefaece85df1441e62179af097458e2bdcf600f8629b977470db1b6db1",
		        "previous": "0000015957d92c9e04c6f3aec8c5b9976f3d25f52ff459c630a01a643af4a88c",
		        "range_proof_root": "4fd9a9189e0965aa9cdeb9cf7873ecd9e6586eac1dd9ca3915bc50824a253b02",
		        "secondary_scaling": 561,
		        "timestamp": "2019-10-03T16:08:11+00:00",
		        "total_difficulty": 1133587428693359,
		        "total_kernel_offset": "0320b6f8a4a4180ed79ecd67c8059c1d7bd74afe144d225395857386e5822314",
		        "version": 2
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
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password))

            result = client_foreign.get_header(
                height=height, hash_=hash_, commit=commit)
            assert result == mocked_response_result

    def test_get_blocks(self):
        with requests_mock.Mocker() as m:
            node_url = 'http://localhost:3413/v2/foreign'
            node_user = 'grin'
            node_password = 'password'
            client_foreign = NodeV2Foreign(
                node_url, node_user, node_password)

            start_height = 2299309
            end_height = 2300309
            max_ = 2
            include_proof = False
            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'get_blocks',
                'params': [start_height, end_height, max_, include_proof]
            }
            mocked_response_result = {
			    "blocks": [
				    {
					    "header": {
						    "cuckoo_solution": [
							    20354215, 100524565, 169529296, 259818619, 261952555, 265003136,
							    290685286, 307792709, 329993483, 331550733, 478902211, 707186317,
							    717277083, 742312701, 763869950, 785680094, 791217416, 1156641404,
							    1244452354, 1277970471, 1405106926, 1663783361, 1701259732, 1795507572,
							    1845900835, 2060172013, 2067055232, 2169213199, 2191128830, 2253855427,
							    2626425322, 2678973678, 2815586448, 2921010487, 3042894274, 3103031603,
							    3492595971, 3603041347, 3853538391, 3974438280, 4199558832, 4262968379
						    ],
						    "edge_bits": 32,
						    "hash": "0004331bb122685f12644e40b163e4557951b2b835ad2493502750ea787af7cc",
						    "height": 2299309,
						    "kernel_mmr_size": 8568165,
						    "kernel_root": "6b4adb9ee193ad043910b5a8c1bac0864ab99f57845101a3b422031bcf5c2ce1",
						    "nonce": 4185528505858938389,
						    "output_mmr_size": 13524183,
						    "output_root": "b642891741b56adaf7762813490d161377d0fbf7b47170d235beef33c25a4d77",
						    "prev_root": "a0ba3206b6a8089ef05690d40767c41cc0514eaa5031ebce1960a7cc2edcc211",
						    "previous": "000207548609a9007eacd7dfcdc8006252d6b1ad70864ea8ddebe4ca9e82bd74",
						    "range_proof_root": "d8cefda00f325fd9a1223454f23276b73d8a1d7c72ec74cdfb9bdf5c77a04dee",
						    "secondary_scaling": 0,
						    "timestamp": "2023-06-05T20:18:45+00:00",
						    "total_difficulty": 2072532663425232,
						    "total_kernel_offset": "b0a0c21326532b4a91c18d2355aedca4d8ed68b77db9882feb85da8120b4f533",
						    "version": 5
					    },
					    "inputs": [
						    "092b140b1500812ac58ef68c17a2bbf2ec3531bcf0ce4dc32bbf8a29351d1784d7",
						    "083b72230921abeacd637dae8505233ab035c20dff1bfdab5ff5bb41b2f5238458"
					    ],
					    "kernels": [
						    {
							    "excess": "08ab720dc374f099e6726e2dceada508a0331bb1f13b8a4e56afde83ff42f7a351",
							    "excess_sig": "6858120e9758d7587e27fd5dc9c26117a2ce0d5a7d871ce805e03eb494bfa1f86a27991865b3ab709064c43692433fd58f008c3bba2c88ad5f95a0c8ff3cf11f",
							    "features": "Plain",
							    "fee": 23500000,
							    "fee_shift": 0,
							    "lock_height": 0
						    },
						    {
							    "excess": "08d0a44b22952b03b29e3d88391102c281dcab4763def22cab65ed45e35b9078e8",
							    "excess_sig": "32f91d5671e334a87843a8b02c550c9e0fbdfe507ee62417cc123b5078d7884701a42e257357a1bed9dc4a8e07540b1629e9fa95a05c44adb5cb001c8fb777ee",
							    "features": "Coinbase",
							    "fee": 0,
							    "fee_shift": 0,
							    "lock_height": 0
						    }
					    ],
					    "outputs": [
						    {
							    "block_height": 2299309,
							    "commit": "0857c94df51dd226fa0c5920aae6d73d069603f973b2e06551698c6d39fdc2c192",
							    "merkle_proof": None,
							    "mmr_index": 13524176,
							    "output_type": "Coinbase",
							    "proof": None,
							    "proof_hash": "0937291a8a3c81cea4421fa0d0b291aacb5d46065cfd93747a15f58d99d781b6",
							    "spent": False
						    },
						    {
							    "block_height": 2299309,
							    "commit": "08d4681b904695edee6e183cd40564ea0f5589b35d4d386da2eb980a6a92b1b307",
							    "merkle_proof": None,
							    "mmr_index": 0,
							    "output_type": "Transaction",
							    "proof": None,
							    "proof_hash": "41694ab6dcd9b1664ca28e79c3302144b99a4c1cb45d13c8728604c1d26e37bf",
							    "spent": True
						    },
						    {
							    "block_height": 2299309,
							    "commit": "08255a260a65fc87cfd924780d896eaadb42468b0fe3ba6adeace378793b5d8172",
							    "merkle_proof": None,
							    "mmr_index": 13524182,
							    "output_type": "Transaction",
							    "proof": None,
							    "proof_hash": "58c77a5716ec4806dbddac64a83d6e4351b6eeffca391be1b11ec74aac0514dc",
							    "spent": False
						    }
					    ]
				    },
				    {
					    "header": {
						    "cuckoo_solution": [
							    898450, 353949138, 440882514, 500154010, 555236503, 615120852,
							    740100750, 754668484, 1056458121, 1071299788, 1130460099, 1414281857,
							    1444894533, 1481124421, 1551877341, 1666859923, 1682642953, 1837365586,
							    1845508478, 1872787697, 2040619654, 2078971700, 2104947318, 2206501084,
							    2233951742, 2360961460, 2378988856, 2402500295, 2438384422, 2532261092,
							    2879360933, 3011869457, 3023365279, 3412207020, 3509607650, 3793770861,
							    3850043972, 3873426868, 3965579806, 4007877324, 4090157476, 4141650723
						    ],
						    "edge_bits": 32,
						    "hash": "00006871e1fb8e7dddcc46343d7fbba14d08946c67b4568f3c2e98ec8c554ae9",
						    "height": 2299310,
						    "kernel_mmr_size": 8568166,
						    "kernel_root": "87184dc2f9efa6467ce797191c5d3ef086403d0103ba0b5adc6a71ed203a053c",
						    "nonce": 13726392224838330049,
						    "output_mmr_size": 13524184,
						    "output_root": "9570fbccef29609c5d3c68b07771bf4e7e80d0b139d9bd0215d1e9d1aaaed813",
						    "prev_root": "df1c67366b9cdd8deea570534a00a320748899e146288be067c0f402038e6aa0",
						    "previous": "0004331bb122685f12644e40b163e4557951b2b835ad2493502750ea787af7cc",
						    "range_proof_root": "987d7aff01e201269d4c6b00e885b9ed9c10f47205edd7727e3490aab953ca80",
						    "secondary_scaling": 0,
						    "timestamp": "2023-06-05T20:19:27+00:00",
						    "total_difficulty": 2072532872584027,
						    "total_kernel_offset": "b0a0c21326532b4a91c18d2355aedca4d8ed68b77db9882feb85da8120b4f533",
						    "version": 5
					    },
					    "inputs": [],
					    "kernels": [
						    {
							    "excess": "08224a7946a75071b127af45496ddd3fc438db325cc35c3e4b0fdf23ed27703dd8",
							    "excess_sig": "d8c81bd8130c30016e38655a32b4c7a1f8fffda34a736dd8cdbcad05d28d09e3708d1f01e21276747eb03f28b9f5a834cb0ef8532330183df2b10d47ae7e68c6",
							    "features": "Coinbase",
							    "fee": 0,
							    "fee_shift": 0,
							    "lock_height": 0
						    }
					    ],
					    "outputs": [
						    {
							    "block_height": 2299310,
							    "commit": "09997d3c1eff72b7efa7bfb52032d713f5907755838c01a6e178a87a0ac170a279",
							    "merkle_proof": None,
							    "mmr_index": 13524184,
							    "output_type": "Coinbase",
							    "proof": None,
							    "proof_hash": "6c2c10af5c4b6d2bcf71084c2bd9685ae91427f03a8b78736ab27d6c5bc7e4db",
							    "spent": False
						    }
					    ]
				    }
			    ],
			    "last_retrieved_height": 2299310
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
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password))

            result = client_foreign.get_blocks(
                start_height, end_height, max_, include_proof=include_proof)
            assert result == mocked_response_result

'''
    def test_(self):
        with requests_mock.Mocker() as m:
            node_url = 'http://localhost:3413/v2/foreign'
            node_user = 'grin'
            node_password = 'password'
            client_foreign = NodeV2Foreign(
                node_url, node_user, node_password)

            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': '',
                'params': []
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
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password))

            result = client_foreign.a()
            assert result == mocked_response_result

'''
