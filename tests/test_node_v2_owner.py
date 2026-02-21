import requests_mock

from grinmw import NodeV2Owner
from tests import GrinAPITestClass, mock_post


class TestNodeOwnerApiV2Methods(GrinAPITestClass):
    def test_get_status(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/owner"
            node_user = "grin"
            node_password = "password"
            client_owner = NodeV2Owner(node_url, node_user, node_password)

            status = {
                "chain": "main",
                "protocol_version": "2",
                "user_agent": "MW/Grin 2.x.x",
                "connections": "8",
                "tip": {
                    "height": 371553,
                    "last_block_pushed": "00001d1623db988d7ed10c5b6319360a52f20c89b4710474145806ba0e8455ec",
                    "prev_block_to_last": "0000029f51bacee81c49a27b4bc9c6c446e03183867c922890f90bb17108d89f",
                    "total_difficulty": 1127628411943045,
                },
                "sync_status": "header_sync",
                "sync_info": {"current_height": 371553, "highest_height": 0},
            }
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_status",
                "params": [],
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

            result = client_owner.get_status()
            assert result == mocked_response_result

    def test_validate_chain(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/owner"
            node_user = "grin"
            node_password = "password"
            client_owner = NodeV2Owner(node_url, node_user, node_password)

            assume_valid_rangeproofs_kernels = False
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "validate_chain",
                "params": [assume_valid_rangeproofs_kernels],
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

            result = client_owner.validate_chain(assume_valid_rangeproofs_kernels)
            assert result == mocked_response_result

    def test_compact_chain(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/owner"
            node_user = "grin"
            node_password = "password"
            client_owner = NodeV2Owner(node_url, node_user, node_password)

            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "compact_chain",
                "params": [],
            }
            mocked_response_result = None
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

            result = client_owner.compact_chain()
            assert result == mocked_response_result

    # no mock data for reset_chain_head in
    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.reset_chain_head

    # no mock data for invalidate_header in
    # https://docs.rs/grin_api/latest/grin_api/owner_rpc/trait.OwnerRpc.html#tymethod.invalidate_header

    def test_get_peers(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/owner"
            node_user = "grin"
            node_password = "password"
            client_owner = NodeV2Owner(node_url, node_user, node_password)

            peer_addr = "70.50.33.130:3414"
            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_peers",
                "params": [peer_addr],
            }
            mocked_response_result = [
                {
                    "addr": "70.50.33.130:3414",
                    "ban_reason": "None",
                    "capabilities": {"bits": 15},
                    "flags": "Defunct",
                    "last_banned": 0,
                    "last_connected": 1570129317,
                    "user_agent": "MW/Grin 2.0.0",
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

            result = client_owner.get_peers(peer_addr=peer_addr)
            assert result == mocked_response_result

    def test_get_connected_peers(self):
        with requests_mock.Mocker() as m:
            node_url = "http://localhost:3413/v2/owner"
            node_user = "grin"
            node_password = "password"
            client_owner = NodeV2Owner(node_url, node_user, node_password)

            expected_request_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "get_connected_peers",
                "params": [],
            }
            mocked_response_result = [
                {
                    "addr": "35.176.195.242:3414",
                    "capabilities": {"bits": 15},
                    "direction": "Outbound",
                    "height": 374510,
                    "total_difficulty": 1133954621205750,
                    "user_agent": "MW/Grin 2.0.0",
                    "version": 1,
                },
                {
                    "addr": "47.97.198.21:3414",
                    "capabilities": {"bits": 15},
                    "direction": "Outbound",
                    "height": 374510,
                    "total_difficulty": 1133954621205750,
                    "user_agent": "MW/Grin 2.0.0",
                    "version": 1,
                },
                {
                    "addr": "148.251.16.13:3414",
                    "capabilities": {"bits": 15},
                    "direction": "Outbound",
                    "height": 374510,
                    "total_difficulty": 1133954621205750,
                    "user_agent": "MW/Grin 2.0.0",
                    "version": 1,
                },
                {
                    "addr": "68.195.18.155:3414",
                    "capabilities": {"bits": 15},
                    "direction": "Outbound",
                    "height": 374510,
                    "total_difficulty": 1133954621205750,
                    "user_agent": "MW/Grin 2.0.0",
                    "version": 1,
                },
                {
                    "addr": "52.53.221.15:3414",
                    "capabilities": {"bits": 15},
                    "direction": "Outbound",
                    "height": 0,
                    "total_difficulty": 1133954621205750,
                    "user_agent": "MW/Grin 2.0.0",
                    "version": 1,
                },
                {
                    "addr": "109.74.202.16:3414",
                    "capabilities": {"bits": 15},
                    "direction": "Outbound",
                    "height": 374510,
                    "total_difficulty": 1133954621205750,
                    "user_agent": "MW/Grin 2.0.0",
                    "version": 1,
                },
                {
                    "addr": "121.43.183.180:3414",
                    "capabilities": {"bits": 15},
                    "direction": "Outbound",
                    "height": 374510,
                    "total_difficulty": 1133954621205750,
                    "user_agent": "MW/Grin 2.0.0",
                    "version": 1,
                },
                {
                    "addr": "35.157.247.209:23414",
                    "capabilities": {"bits": 15},
                    "direction": "Outbound",
                    "height": 374510,
                    "total_difficulty": 1133954621205750,
                    "user_agent": "MW/Grin 2.0.0",
                    "version": 1,
                },
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

            result = client_owner.get_connected_peers()
            assert result == mocked_response_result

    def test_ban_peer(self):
        with requests_mock.Mocker() as m:
            node_url = 'http://localhost:3413/v2/owner'
            node_user = 'grin'
            node_password = 'password'
            client_owner = NodeV2Owner(
                node_url, node_user, node_password)

            peer_addr = '70.50.33.130:3414'
            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'ban_peer',
                'params': [peer_addr]
            }
            mocked_response_result = None
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

            result = client_owner.ban_peer(peer_addr)
            assert result == mocked_response_result


    def test_unban_peer(self):
        with requests_mock.Mocker() as m:
            node_url = 'http://localhost:3413/v2/owner'
            node_user = 'grin'
            node_password = 'password'
            client_owner = NodeV2Owner(
                node_url, node_user, node_password)

            peer_addr = '70.50.33.130:3414'
            expected_request_body = {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'unban_peer',
                'params': [peer_addr]
            }
            mocked_response_result = None
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

            result = client_owner.unban_peer(peer_addr)
            assert result == mocked_response_result
