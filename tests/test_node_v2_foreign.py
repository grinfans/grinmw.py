import requests_mock

from grinmw import NodeV2Foreign
from tests import GrinAPITestClass, mock_post


class TestNodeForeignApiV2Methods(GrinAPITestClass):
    def test_get_block(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            height = 374274
            hash_ = None
            commit = None
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_block",
                "params": [height, hash_, commit],
            }
            mocked_response_result = {
                "header": {
                    "cuckoo_solution": [
                        1263501,
                        14648727,
                        42430559,
                        58137254,
                        68666726,
                        72784903,
                        101936839,
                        104273571,
                        123886748,
                        131179768,
                        155443226,
                        162493783,
                        164784425,
                        167313215,
                        169806918,
                        183041591,
                        184403611,
                        210351649,
                        215159650,
                        239995384,
                        240935454,
                        257742462,
                        280820644,
                        300143903,
                        303146496,
                        311804841,
                        341039986,
                        354918290,
                        363508555,
                        377618528,
                        396693709,
                        397417856,
                        399875872,
                        413238540,
                        413767813,
                        432697194,
                        436903767,
                        447257325,
                        453337210,
                        459401597,
                        496068509,
                        511300624,
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
                    "version": 2,
                },
                "inputs": [],
                "kernels": [
                    {
                        "excess": "08761e9cb1eea5bfcf771d1218b5ec802798d6eecaf75faae50ba3a1997aaef009",
                        "excess_sig": "971317046c533d21dff3e449cc9380c2be10b0274f70e009aa2453f755239e3299883c09a1785b15a141d89d563cdd59395886c7d63aba9c2b6438575555e2c4",
                        "features": "Coinbase",
                        "fee": 0,
                        "lock_height": 0,
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
                        "spent": False,
                    }
                ],
            }
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_block(height, hash_, commit)
            assert result == mocked_response_result

    def test_get_header(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            height = None
            hash_ = "00000100c54dcb7a9cbb03aaf55da511aca2c98b801ffd45046b3991e4f697f9"
            commit = None
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_header",
                "params": [height, hash_, commit],
            }
            mocked_response_result = {
                "cuckoo_solution": [
                    9886309,
                    35936712,
                    43170402,
                    48069549,
                    70022151,
                    97464262,
                    107044653,
                    108342481,
                    118947913,
                    130828808,
                    144192311,
                    149269998,
                    179888206,
                    180736988,
                    207416734,
                    227431174,
                    238941623,
                    245603454,
                    261819503,
                    280895459,
                    284655965,
                    293675096,
                    297070583,
                    299129598,
                    302141405,
                    313482158,
                    321703003,
                    351704938,
                    376529742,
                    381955038,
                    383597880,
                    408364901,
                    423241240,
                    436882285,
                    442043438,
                    446377997,
                    470779425,
                    473427731,
                    477149621,
                    483204863,
                    496335498,
                    534567776,
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
                "version": 2,
            }
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_header(
                height=height, hash_=hash_, commit=commit
            )
            assert result == mocked_response_result

    def test_get_blocks(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            start_height = 2299309
            end_height = 2300309
            max_ = 2
            include_proof = False
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_blocks",
                "params": [start_height, end_height, max_, include_proof],
            }
            mocked_response_result = {
                "blocks": [
                    {
                        "header": {
                            "cuckoo_solution": [
                                20354215,
                                100524565,
                                169529296,
                                259818619,
                                261952555,
                                265003136,
                                290685286,
                                307792709,
                                329993483,
                                331550733,
                                478902211,
                                707186317,
                                717277083,
                                742312701,
                                763869950,
                                785680094,
                                791217416,
                                1156641404,
                                1244452354,
                                1277970471,
                                1405106926,
                                1663783361,
                                1701259732,
                                1795507572,
                                1845900835,
                                2060172013,
                                2067055232,
                                2169213199,
                                2191128830,
                                2253855427,
                                2626425322,
                                2678973678,
                                2815586448,
                                2921010487,
                                3042894274,
                                3103031603,
                                3492595971,
                                3603041347,
                                3853538391,
                                3974438280,
                                4199558832,
                                4262968379,
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
                            "version": 5,
                        },
                        "inputs": [
                            "092b140b1500812ac58ef68c17a2bbf2ec3531bcf0ce4dc32bbf8a29351d1784d7",
                            "083b72230921abeacd637dae8505233ab035c20dff1bfdab5ff5bb41b2f5238458",
                        ],
                        "kernels": [
                            {
                                "excess": "08ab720dc374f099e6726e2dceada508a0331bb1f13b8a4e56afde83ff42f7a351",
                                "excess_sig": "6858120e9758d7587e27fd5dc9c26117a2ce0d5a7d871ce805e03eb494bfa1f86a27991865b3ab709064c43692433fd58f008c3bba2c88ad5f95a0c8ff3cf11f",
                                "features": "Plain",
                                "fee": 23500000,
                                "fee_shift": 0,
                                "lock_height": 0,
                            },
                            {
                                "excess": "08d0a44b22952b03b29e3d88391102c281dcab4763def22cab65ed45e35b9078e8",
                                "excess_sig": "32f91d5671e334a87843a8b02c550c9e0fbdfe507ee62417cc123b5078d7884701a42e257357a1bed9dc4a8e07540b1629e9fa95a05c44adb5cb001c8fb777ee",
                                "features": "Coinbase",
                                "fee": 0,
                                "fee_shift": 0,
                                "lock_height": 0,
                            },
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
                                "spent": False,
                            },
                            {
                                "block_height": 2299309,
                                "commit": "08d4681b904695edee6e183cd40564ea0f5589b35d4d386da2eb980a6a92b1b307",
                                "merkle_proof": None,
                                "mmr_index": 0,
                                "output_type": "Transaction",
                                "proof": None,
                                "proof_hash": "41694ab6dcd9b1664ca28e79c3302144b99a4c1cb45d13c8728604c1d26e37bf",
                                "spent": True,
                            },
                            {
                                "block_height": 2299309,
                                "commit": "08255a260a65fc87cfd924780d896eaadb42468b0fe3ba6adeace378793b5d8172",
                                "merkle_proof": None,
                                "mmr_index": 13524182,
                                "output_type": "Transaction",
                                "proof": None,
                                "proof_hash": "58c77a5716ec4806dbddac64a83d6e4351b6eeffca391be1b11ec74aac0514dc",
                                "spent": False,
                            },
                        ],
                    },
                    {
                        "header": {
                            "cuckoo_solution": [
                                898450,
                                353949138,
                                440882514,
                                500154010,
                                555236503,
                                615120852,
                                740100750,
                                754668484,
                                1056458121,
                                1071299788,
                                1130460099,
                                1414281857,
                                1444894533,
                                1481124421,
                                1551877341,
                                1666859923,
                                1682642953,
                                1837365586,
                                1845508478,
                                1872787697,
                                2040619654,
                                2078971700,
                                2104947318,
                                2206501084,
                                2233951742,
                                2360961460,
                                2378988856,
                                2402500295,
                                2438384422,
                                2532261092,
                                2879360933,
                                3011869457,
                                3023365279,
                                3412207020,
                                3509607650,
                                3793770861,
                                3850043972,
                                3873426868,
                                3965579806,
                                4007877324,
                                4090157476,
                                4141650723,
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
                            "version": 5,
                        },
                        "inputs": [],
                        "kernels": [
                            {
                                "excess": "08224a7946a75071b127af45496ddd3fc438db325cc35c3e4b0fdf23ed27703dd8",
                                "excess_sig": "d8c81bd8130c30016e38655a32b4c7a1f8fffda34a736dd8cdbcad05d28d09e3708d1f01e21276747eb03f28b9f5a834cb0ef8532330183df2b10d47ae7e68c6",
                                "features": "Coinbase",
                                "fee": 0,
                                "fee_shift": 0,
                                "lock_height": 0,
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
                                "spent": False,
                            }
                        ],
                    },
                ],
                "last_retrieved_height": 2299310,
            }
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_blocks(
                start_height, end_height, max_, include_proof=include_proof
            )
            assert result == mocked_response_result

    def test_get_version(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_version",
                "params": [],
            }
            mocked_response_result = {
                "node_version": "2.1.0-beta.2",
                "block_header_version": 2,
            }
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_version()
            assert result == mocked_response_result

    def test_get_tip(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_tip",
                "params": [],
            }
            mocked_response_result = {
                "height": 374350,
                "last_block_pushed": "000000543c69a0306b5463b92939643442a44a6d9be5bef72bea9fc1d718d310",
                "prev_block_to_last": "000001237c6bac162f1add2b122fab6a254b9fcc2c4b4c8c632a8c39855521f1",
                "total_difficulty": 1133621604919005,
            }
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_tip()
            assert result == mocked_response_result

    def test_get_kernel(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            excess = (
                "09c868a2fed619580f296e91d2819b6b3ae61ab734bf3d9c3eafa6d9700f00361b"
            )
            min_height = None
            max_height = None
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_kernel",
                "params": [excess, min_height, max_height],
            }
            mocked_response_result = {
                "excess": "09c868a2fed619580f296e91d2819b6b3ae61ab734bf3d9c3eafa6d9700f00361b",
                "excess_sig": "1720ec1b94aa5d6ba4d567f7446314f9a6d064eea69c5675cc5659f65f290d80b0e9e3a48d818cadba0a4e894bbc6eb6754b56f53813e2ee0b1447969894ca4a",
                "features": "Coinbase",
            }
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_kernel(
                excess, min_height=min_height, max_height=max_height
            )
            assert result == mocked_response_result

    def test_get_outputs(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            commits = [
                "09bab2bdba2e6aed690b5eda11accc13c06723ca5965bb460c5f2383655989af3f",
                "08ecd94ae293863286e99d37f4685f07369bc084ba74d5c59c7f15359a75c84c03",
            ]
            start_height = 376150
            end_height = 376154
            include_proof = True
            include_merkle_proof = True
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_outputs",
                "params": [
                    commits,
                    start_height,
                    end_height,
                    include_proof,
                    include_merkle_proof,
                ],
            }
            mocked_response_result = {}
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_outputs(
                commits,
                start_height=start_height,
                end_height=end_height,
                include_proof=include_proof,
                include_merkle_proof=include_merkle_proof,
            )
            assert result == mocked_response_result

    def test_get_unspent_outputs(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            start_index = 1
            max_ = 2
            end_index = None
            include_proof = True
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_unspent_outputs",
                "params": [start_index, end_index, max_, include_proof],
            }
            mocked_response_result = {}
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_unspent_outputs(
                start_index, max_, end_index=None, include_proof=True
            )
            assert result == mocked_response_result

    def test_get_pmmr_indices(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            start_block_height = 100
            end_block_height = 100
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_pmmr_indices",
                "params": [start_block_height, end_block_height],
            }
            mocked_response_result = {
                "highest_index": 398,
                "last_retrieved_index": 2,
                "outputs": [],
            }
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_pmmr_indices(
                start_block_height, end_block_height=end_block_height
            )
            assert result == mocked_response_result

    def test_get_pool_size(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_pool_size",
                "params": [],
            }
            mocked_response_result = 1
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_pool_size()
            assert result == mocked_response_result

    def test_get_stempool_size(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_stempool_size",
                "params": [],
            }
            mocked_response_result = 0
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_stempool_size()
            assert result == mocked_response_result

    def test_get_unconfirmed_transactions(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_unconfirmed_transactions",
                "params": [],
            }
            mocked_response_result = [
                {
                    "src": "Broadcast",
                    "tx": {
                        "body": {
                            "inputs": [
                                {
                                    "commit": "0992ce1827ec349e9f339ce183ffd01db39bf43999799d8191bfc267a58f0a715c",
                                    "features": "Coinbase",
                                },
                                {
                                    "commit": "0943a3c4ee4a22a5b086c26f8e6dc534204dafde0cf4c07e0c468d224dd79127ec",
                                    "features": "Plain",
                                },
                            ],
                            "kernels": [
                                {
                                    "excess": "083c49eaaf6380d44596f52cce4cf278cfac6dd34fbef73981002d8f1e8ee8abe4",
                                    "excess_sig": "3f011e7e288231d67f42cb4f6416c4720e6170d5e3c805a52d33aa4521328f9be0303be654bc8ddcd3111aadc27c848b9cf07e0a70885ef79be70b7bb70f8c75",
                                    "features": {"Plain": {"fee": 7000000}},
                                }
                            ],
                            "outputs": [
                                {
                                    "commit": "0873fafd4a0e4f365939e24c68eeb18aafc6674ca244a364dcdbfa8fa525e7bae1",
                                    "features": "Plain",
                                    "proof": "4b675be40672d5965c43d9f03880560a8ac784ee3de8768e28c236a4bc43b8c3d4bc83dee00d2b96530af9607c3b91d9a828f0234bf2aaf7e7c0e9cf936db69c04ca1b267668fbdb2f08ce05c8b119c9d886ceaafb4634b7fae7ea01966ad825dddc9ffab8093155d9c5d268160b86fcad95f4f5e66bf46ff642a51629dbdfd7bba7936846915b925d547337a1b95c33030fad4178468825936242e631797aa3a8f0a5ae0d23040938622648c8432fc247a902abad27e383affb4ec518e4f6f55f55e264bc0f99957be203cfb26d4b8e561fb36da55a50b6ef5861134c484556d701133e1dceda5ea53e731184e0a11f33d06e13ca37d03d39dd047170580534b049862fcd6c73decc7c0af45a267ed148fe6ef2cc375ffebfa8187d2fa0a134428a036d2ec1f65d3ce036b955730fc1ee43b23b574bae2b58b7adfa2a7a45cdec393d9b658857c911560aa3c44cf4435a99d68f3dbc81c82ea43e426ef0198148a90336ee72472aab5f7feea1df93ec830fe5ec642c93c1046dec955df361bfdc3ab74477f847a1b72e8735ef65a8a6d1680745c0152bfb5cbb2a4b4671491a253a1a09d5a07d55f4872c9f0a3d25e07b257926629d5bb96aed96f5debab02503eb0ac45033323cc5a46c8e5d4469ee9f3dd618a20d54d6f5740c010fe5a0fe853efeb253a6df196bd24469ac51c1be8ba84737cecdb5ab73d7c52570d2273621fb69bd7ed985bbc6999dbd2d6fd2687ae44a391d604ff232cc6b3fbedd5d1cd0cd8c658c5d56069b5a5099cc5c9f48bbf7d7e83b4f9a7bdef6eabd164c8395468f818e8cd8c1c800bc3adfd66dbcb247d1bda5a7af38c288c0beb8e0d9160bf67500094530a0f8be52e97b5c2114f5a4a333a11c7f37f4c47a437422455d8cbcfa770cdc85ec55accf48cf14550b07f1346a02fccdf280fcb24c1fb38751d889a17e",
                                },
                                {
                                    "commit": "08de9e42d361cabd99e566c67f7f8599c7e6985cd285a841277f1aeb89ad6c8fe3",
                                    "features": "Plain",
                                    "proof": "5eb7afa00e9681e3b6425fb4256c96905303505787d6a065e88a50154410b9a371b0f879d3f97cfa00425e9c8266e180188656acdbb46cacfdfb159fb135c5eb03b08be3c231c4b21df777da2e2afe8d30db91e602dc4ceed71aeb1b45a0266cfeadc4acbf9fdf7a67f67408fbbea7bf14182bc407373d243c6875373b655695604deb575369a9b28274885601b338882219c7f508aa2a0ae1d02736af2249327145f1d3d00093f9587f0e0b408692700fac0f2a048c329e81cabaa4b997dd88923fe97420125f394e21b4835e36cce9de383d9e223df1b5a6ba6f48ffeac315991189dc2716cc7ec07f6ccc8062344d5ed4fcaddf9070f44f0c59ffe8160d1f6fdfe42b40066f51e687d38b6b5255771800ac060bd8034cd68d14eee1b2f43b6d7bf20d71549ea9a50006dd30b9a795e785385801546eb9a83721a09fc34d3b69d4ccdc0ff0fb74d224048aeb66ecff5515296cadd57f42e0717cbba7c70719a10c007db4520e868efe98a51001b67952d7bda3174195a3d76b93ee4dac60137a38b2e8309cad13ef1cfb6c467f1969385e5b334b52f4fd55da440e036d2a428e9f3be905d79f717c169060468acc6d469636fed098b1aba5cd055a120314bcab55d5b8b6889321edf373517e93ef67fbe74557ec6c0211265efefa25a34ac267cf1db891c47163bfed20d2b535abfe60390c2844dcef5f0aad5fa7f1db9f726d7f223c025861069603936a22377707cdd3915e762e7061132124c716212b0e91bb7fc5d7816366f5d169d93fe75669a6ba19057bb2450958aa6f5ada09042570f46215af5a41b623d140be574b7a8c9ab24ea48da416dbe6ec0fa3b889206fb804df8d69805ceb80f1e9d4e8b664b3939491cba946d87585c830e3dab0638fa279b5e911642f18452e2731764aa62f92bbcf194c97f344c90c1931fd2c3af4bcf6b0",
                                },
                            ],
                        },
                        "offset": "0eb2c2669ce918675c72697891e5527bd13da5a499396381409219b8bbbd8129",
                    },
                    "tx_at": "2019-10-07T16:20:08.709114Z",
                }
            ]
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.get_unconfirmed_transactions()
            assert result == mocked_response_result

    def test_push_transaction(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/foreign"
            node_user = "grin"
            node_password = "password"
            client_foreign = NodeV2Foreign(node_url, node_user, node_password)

            tx = {
                "body": {
                    "inputs": [
                        {
                            "commit": "0904cbd34d0745eb00ffc3e95c9f4746738794d00268e243e9b57163a73b384102",
                            "features": "Coinbase",
                        }
                    ],
                    "kernels": [
                        {
                            "excess": "08385257d22f1b8a758903f78ae12545245d620cffc50e7ee7bc852c5815513dc7",
                            "excess_sig": "e001a7349fd40d4a9dfc1df275d30906fb3b304f8c7892a20ed5c9b10923c871cbabedcf322511a9ce56f10113b48855441f681280133e121b25ea1ff7efad9e",
                            "features": {"Plain": {"fee": 8000000}},
                        }
                    ],
                    "outputs": [
                        {
                            "commit": "087c3ca7419751e96cdae4908bb8a92fc2826f2ad36690420b905d51beb7409ca0",
                            "features": "Plain",
                            "proof": "379ae236937883c2e1e613fb30f1b18d2a44d4173360e94bcd07862aafaf81b3aaa1154d67287cc03efde0d3981c6da8a18e2e426f5c30afc0f2e3a75012448402d8d56df52b87f4815575a56d4da174f8187e4faae64bf883b249ceed694271f84ef62a3711d36c997dff7a11111419011e36e3a070b7552415a55faaa3999f99439edccdfe5313277147fdb42be1798442bb225c2b546f5347920584b365aa81a0365b4a706c97c89617b0e6218d2c9bc15805caab27c438ed06340cc4f8dc7bfca0e9d38864c88bb0c834372f6b662b9159134f3f8ec9b8a87878739a7e516b97419ac29e1d4a2b250321470a9a6b98d07065bb7e79afc25a5ab6fc47108f53223078a64502bd4af1a109641447dab82741ebe3fbdbd803ee7a42fe2554e78fa86bd1d1e6e3b913118e9419b0be6f976b2404447d943b5f1bac19a5809fd6834797945a62d21b1ecb6ddebbc5ef94ca9e704d033bd64afde67bd3e06e2cca3bb10190188afc0af80b48dd862b86753d8b4af314763324deb1c97cf020cb87285a47cd28874bb91c6cdf858965e8b9daafbcbc1b4817d334a97d7e25e01b2d072d8dcc6418e3dc7b8e7712632f939238e65ed0731c7af02d55a8884cd8f7f88dc0f63a21955a7364562532f5716c89e14f8f23ad78f6fe2f1649e13ea8f8185f3ee63cc174684d1ef8d8c33fb25bc802f8e05e53fe200b1ea5231f588a020942e6fd7eec67301700088dae8816c16a337120063c21e1604e009df932032812f88be6473af13f802b42d8ad6fc14230fbe13ede178319a7b6540656234ec1f2fcfa70f6faa9c4b6b8150b81fe0fdc273a9bb385d766a02041a5c3f58471d42059c17d84d13ad592aa0ccf337970e7eef06f306b13288795123c9c005b815d848f359b23450656b310f09cda9ad4b7b6931805d47dcd10a8745d834a984e2055168ac3",
                        },
                        {
                            "commit": "09a7b2c1d4b346c4ebe9c6c979e32e7740446624d5439d9d7abb82166c2545e5be",
                            "features": "Plain",
                            "proof": "5fb0ee4093a153e2ed173207dbfa02b4d185f1f313ea4cbf222558819074543f19e9bcdb595a23d4ee971aafcc614b6d2774e22cee6627bc4388297fe6ebf03e0d422f3eb8003cc8516417a6b32eb22f87e1745e0ae5bf1733f2ea253399719b1ef0067934dc548c58729604d24a44040165b32d05e82c9efc9a1f30151dd73ce893ae94709ec2fe5d0f409bb54a86604f0e92915b4f93e7adde823eccf87830ae91d71a7b99967dbcc8531fee44c20c24fb6fe2a34fe86ba5da3a9235cbcdcde033ead57d65c03903a9c9ed877bf0fab9f26d08552c64ea668d5408c84b74bc3ac8335aaaa04ebcf523d36d2207fb8770e976b6fde7d04e2148de5a4169c60b1958bb840b79a8c8f356e1f1fadc35a5a7e276fcd67c354cde546548c9bf788981f38edf5a406977826aa4524004e770b3d3cd6b26f0dc99729ffd9929fa4509b145ef0c3e4293e71b964da731a47cc9f082350acf32afb64b3b12f8383c8f2cc9880131a80ea957b2908c92f21d2db7aa5d67bafb11eb07674e52b920e67a86259dd9c5dcdd18bad182fd85ec4b659c47ea2e2e8a89c57e4d2cde87958fc2ab932e169f6805d2fb14549ac93807bc426eb4cf6d29ff6a4cf22e35dbb27f04211b06b65173501c17a3bb3ff0eecc9bb05dca23379abe457ca3010ebea69e1a2f7f3ed6531bf766007cdd1ac7d6c762785fb56f36194cc2ccaee76a499a7383288e84981b103d76cbe007f66c913eacb277746e78ae08627b279ac1f9a43ab284d8a3b32c6edcd2ea99e8ea836b31a1e2582be6c41f2282cf5fc7bdb95e4b412a5eeccad29670197873a888a100c4b2704ce75137fc997a5632d81001f9b57300a9bf99edd857065be83f835e4c49d852165ba18e1c96316c153459a913773d5d86ddc26c5cd1fff38a8fbb62506b0aef6076382674c0fa95a50a03b0c3df0a688a2cbf",
                        },
                    ],
                },
                "offset": "0ec14d3875ad5a366418256fe65bad2a4d4ff1914e1b9488db72dd355138ca3a",
            }
            fluff = True
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "push_transaction",
                "params": [tx, fluff],
            }
            mocked_response_result = {}
            mocked_response = {
                "id": 1,
                "jsonrpc": "2.0",
                "result": {"Ok": mocked_response_result},
            }

            mock_post(
                m,
                node_url,
                mocked_response,
                expected_body=expected_request_body,
                status_code=200,
                expected_auth=(node_user, node_password),
            )

            result = client_foreign.push_transaction(tx, fluff=fluff)
            assert result == mocked_response_result
