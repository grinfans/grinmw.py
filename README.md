# grinmw.py

Grin is a privacy-preserving digital currency built openly by developers distributed all over the world. Check [grin.mw](https://grin.mw/) to know more!

This module provides Python wrappers for

* [Grin Wallet API V3](https://docs.grin.mw/wiki/api/wallet-api/)
* [Grin Node API V2](https://docs.grin.mw/wiki/api/node-api/)

Install with

```
pip install grinmw
```

If you need help please check how to reach our [community](https://grin.mw/community).

## Examples

### Node Foreign API V2

```python
from grinmw import NodeV2Foreign

import pprint
from pathlib import Path
home = str(Path.home())

pp = pprint.PrettyPrinter(indent=4)

foreign_api_url = 'http://localhost:3413/v2/foreign'

# change to your grin owner_api sercret file
foreign_api_sercet_file = os.path.join(home, '.grin/main/.foreign_api_secret')
foreign_api_user = 'grin'
foreign_api_password = open(foreign_api_sercet_file).read().strip()

node = NodeV2Foreign(foreign_api_url, foreign_api_user, foreign_api_password)
pp.pprint(node.get_version())
pp.pprint(node.get_tip())
pp.pprint(node.get_kernel('096a7303ab9e3a68cf0b3d70d6ec61311efaf0f33f2ac251bff2a4da45908d3f15'))
pp.pprint(node.get_kernel('08f0a2b7e3ddd0ccc60ac147e93f3e8b01ede591d0da08ba93333e3c73fd45c1cf'))
```

### Node Owner API V2

```python
from grinmw import NodeV2Owner

import pprint
from pathlib import Path
home = str(Path.home())

pp = pprint.PrettyPrinter(indent=4)
owner_api_url = 'http://localhost:3413/v2/owner'

# change to your grin owner_api secret file
owner_api_sercet_file = os.path.join(home, '.grin/main/.api_secret')
owner_api_user = 'grin'
owner_api_password = open(owner_api_sercet_file).read().strip()

node = NodeV2Foreign(owner_api_url, owner_api_user, owner_api_password)
pp.pprint(node.get_status())
assume_valid_rangeproofs = False
pp.pprint(node.validate_chain(assume_valid_rangeproofs))
pp.pprint(node.get_peers())
pp.pprint(node.get_connected_peers())
```

### Wallet Owner API V3

```python
from grinmw import WalletV3Owner

import pprint, os

pp = pprint.PrettyPrinter(indent=4)
api_url = 'http://localhost:3420/v3/owner'

# change to your grin owner_api sercret file
api_sercet_file = '/home/ubuntu/.grin/main/.owner_api_secret'
api_user = 'grin'
api_password = open(api_sercet_file).read().strip()
wallet = WalletV3Owner(api_url, api_user, api_password)
wallet.init_secure_api()

# change to you wallet password
wallet_password = '123'

wallet.open_wallet(None, wallet_password)
pp.pprint(wallet.node_height())
pp.pprint(wallet.get_slatepack_address())

# send to gate.io
send_args = {
    'src_acct_name': None,
    'amount': int(2.67020546 * 1000000000),
    'minimum_confirmations': 10,
    'max_outputs': 500,
    'num_change_outputs': 1,
    'selection_strategy_is_use_all': False,
    'target_slate_version': None,
    'payment_proof_recipient_address': 'grin1n26np6apy07576qx6yz4qayuwxcpjvl87a2mjv3jpk6mnyz8y4vq65ahjm',
    'ttl_blocks': None,
    'send_args': {
        "dest": 'grin1n26np6apy07576qx6yz4qayuwxcpjvl87a2mjv3jpk6mnyz8y4vq65ahjm',
        "post_tx": True,
        "fluff": True,
        "skip_tor": False
    }
}
print(wallet.init_send_tx(send_args))
```


### Wallet Foreign API V2

```python
from grinmw import WalletV2Foreign

import pprint, os

pp = pprint.PrettyPrinter(indent=4)
api_url = 'http://localhost:3415/v2/foreign'

api_password = open(api_sercet_file).read().strip()
wallet = WalletV2Foreign(api_url)

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
            "part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be7bf31d80494f5e4a3d656649b1610c61a268f9cafcfc604b5d9f25efb2aa3c5",
        }
    ],
    "coms": [
        {
            "f": 1,
            "c": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
        },
        {
            "f": 1,
            "c": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
        },
        {
            "c": "09ede20409d5ae0d1c0d3f3d2c68038a384cdd6b7cc5ca2aab670f570adc2dffc3",
            "p": "6d86fe00220f8c6ac2ad4e338d80063dba5423af525bd273ecfac8ef6b509192732a8cd0c53d3313e663ac5ccece3d589fd2634e29f96e82b99ca6f8b953645a005d1bc73493f8c41f84fb8e327d4cbe6711dba194a60db30700df94a41e1fda7afe0619169389f8d8ee12bddf736c4bc86cd5b1809a5a27f195209147dc38d0de6f6710ce9350f3b8e7e6820bfe5182e6e58f0b41b82b6ec6bb01ffe1d8b3c2368ebf1e31dfdb9e00f0bc68d9119a38d19c038c29c7b37e31246e7bba56019bc88881d7d695d32557fc0e93635b5f24deffefc787787144e5de7e86281e79934e7e20d9408c34317c778e6b218ee26d0a5e56b8b84a883e3ddf8603826010234531281486454f8c2cf3fee074f242f9fc1da3c6636b86fb6f941eb8b633d6e3b3f87dfe5ae261a40190bd4636f433bcdd5e3400255594e282c5396db8999d95be08a35be9a8f70fdb7cf5353b90584523daee6e27e208b2ca0e5758b8a24b974dca00bab162505a2aa4bcefd8320f111240b62f861261f0ce9b35979f9f92da7dd6989fe1f41ec46049fd514d9142ce23755f52ec7e64df2af33579e9b8356171b91bc96b875511bef6062dd59ef3fe2ddcc152147554405b12c7c5231513405eb062aa8fa093e3414a144c544d551c4f1f9bf5d5d2ff5b50a3f296c800907704bed8d8ee948c0855eff65ad44413af641cdc68a06a7c855be7ed7dd64d5f623bbc9645763d48774ba2258240a83f8f89ef84d21c65bcb75895ebca08b0090b40aafb7ddef039fcaf4bad2dbbac72336c4412c600e854d368ed775597c15d2e66775ab47024ce7e62fd31bf90b183149990c10b5b678501dbac1af8b2897b67d085d87cab7af4036cba3bdcfdcc7548d7710511045813c6818d859e192e03adc0d6a6b30c4cbac20a0d6f8719c7a9c3ad46d62eec464c4c44b58fca463fea3ce1fc51",
        },
    ],
}
pp.pprint(wallet.finalize_tx(slate))
```

More examples in tests suite.
