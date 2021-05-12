import os, requests
from grinmw.wallet_v3 import WalletV3

def http_send(wallet, amount, url, ttl_blocks=None):
    tx_data = {
        'src_acct_name': None,
        'amount': int(amount),
        'minimum_confirmations': 10,
        'max_outputs': 500,
        'num_change_outputs': 1,
        'selection_strategy_is_use_all': False,
        'target_slate_version': None,
        'payment_proof_recipient_address': None,
        'ttl_blocks': ttl_blocks,
        'send_args': None
    }
    slate = wallet.init_send_tx(tx_data)
    tx_slate_id = slate['id']
    slatepack = wallet.create_slatepack_message(slate, [], 0)

    if url.endswith('/'):
        url = url + 'v2/foreign'
    else:
        url = url + '/v2/foreign'
    payload = {
        'jsonrpc': '2.0',
        'id': 0,
        'method': 'receive_tx',
        'params': [slate, None, None],
    }
    resp = requests.post(url, json=payload)
    slate2 = resp.json()['result']['Ok']
    wallet.tx_lock_outputs(slate)
    slate_finalized = wallet.finalize_tx(slate2)
    #success return True
    return tx_slate_id, slate_finalized, wallet.post_tx(slate_finalized)

if __name__ == '__main__':
    from pathlib import Path
    import argparse
    from decimal import Decimal
    parser = argparse.ArgumentParser(description='send grin use http/https')
    parser.add_argument('amount', metavar='1', type=str, nargs=1,
                    help='the amount of grin to send')
    parser.add_argument('-u', '--url', dest='url', type=str,
                    help='the http/https url to where grin will be sent ')

    args = parser.parse_args()
    amount = int(Decimal(args.amount[0]) * 1000000000)

    home = str(Path.home())
    api_url = 'http://localhost:3420/v3/owner'
    api_sercet_file = os.path.join(home, '.grin/main/.owner_api_secret')
    api_user = 'grin'
    api_password = open(api_sercet_file).read().strip()
    wallet = WalletV3(api_url, api_user, api_password)
    wallet.init_secure_api()
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    wallet_password = input('input your wallet password? ')
    wallet.open_wallet(None, wallet_password)

    result = http_send(wallet, amount, args.url)
    print(result[0])


