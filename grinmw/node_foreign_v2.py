from grinmw.node_v2_interface import NodeError, NodeV2Interface

class NodeForeignV2(NodeV2Interface):
    def __init__(
            self, foreign_api_url, foreign_api_user, foreign_api_password):
        owner_api_url = None
        owner_api_user = None
        owner_api_password = None
        super().__init__(
            foreign_api_url, foreign_api_user, foreign_api_password,
            owner_api_url, owner_api_user, owner_api_password)

    def post(self, method, params):
        return super().post(method, params, 'foreign')

    # methods
    def get_header(self, height=None, hash_=None, commit=None):
        resp = self.post('get_header', [height, hash_, commit])
        return resp["result"]["Ok"]

    def get_block(self, height=None, hash_=None, commit=None):
        resp = self.post('get_block', [height, hash_, commit])
        return resp["result"]["Ok"]

    def get_version(self):
        resp = self.post('get_version', [])
        return resp["result"]["Ok"]

    def get_tip(self):
        resp = self.post('get_tip', [])
        return resp["result"]["Ok"]

    def get_kernel(self, kernel, min_height=None, max_height=None):
        resp = self.post(
            'get_kernel', [kernel, min_height, max_height])
        return resp["result"].get("Ok")

    def get_outputs(
            self, commits, start_height=None, end_height=None,
            include_proof=False, include_merkle_proof=False):
        resp = self.post(
            'get_outputs',
            [
                commits,
                start_height,
                end_height,
                include_proof,
                include_merkle_proof
            ])
        return resp["result"].get("Ok")

    def get_unspent_outputs(
            self, start_index, _max, include_proof=False, end_index=None):
        resp = self.post(
            'get_unspent_outputs',
            [
                start_index,
                end_index,
                _max,
                include_proof
            ])
        return resp["result"].get("Ok")

    def get_pmmr_indices(self, start_block_height, end_block_height=None):
        resp = self.post(
            'get_pmmr_indices',
            [
                start_index,
                end_index
            ])
        return resp["result"].get("Ok")

    def get_pool_size(self):
        resp = self.post('get_pool_size', [])
        return resp["result"].get("Ok")

    def get_stempool_size(self):
        resp = self.post('get_stempool_size', [])
        return resp["result"].get("Ok")

    def get_unconfirmed_transactions(self):
        resp = self.post('get_unconfirmed_transactions', [])
        return resp["result"].get("Ok")

    def push_transaction(self, tx, fluff=False):
        resp = self.post('push_transaction', [tx, fluff])
        return resp["result"].get("Ok")
