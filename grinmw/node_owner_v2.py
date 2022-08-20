from grinmw.node_v2_interface import NodeError, NodeV2Interface

class NodeOwnerV2(NodeV2Interface):
    def __init__(
            self, owner_api_url, owner_api_user, owner_api_password):
        foreign_api_url = None
        foreign_api_user = None
        foreign_api_password = None
        super().__init__(
            foreign_api_url, foreign_api_user, foreign_api_password,
            owner_api_url, owner_api_user, owner_api_password)

    def post(self, method, params):
        return super().post(method, params, 'owner')

    # methods
    def ban_peer(self, peers):
        resp = self.post('ban_peer', peers)
        return resp["result"]["Ok"]

    def unban_peer(self, peers):
        resp = self.post('unban_peer', peers)
        return resp["result"]["Ok"]

    def compact_chain(self):
        resp = self.post('compact_chain', [])
        return resp["result"]["Ok"]

    def get_connected_peers(self):
        resp = self.post('get_connected_peers', [])
        return resp["result"]["Ok"]

    def get_peers(self, peers):
        resp = self.post('get_peers', peers)
        return resp["result"]["Ok"]

    def get_status(self):
        resp = self.post('get_status', [])
        return resp["result"]["Ok"]

    def validate_chain(self):
        resp = self.post('validate_chain', [])
        return resp["result"]["Ok"]
