from datetime import datetime
import sys, json, requests, hashlib, base64

def get_merkle_root(transactions):
    lap_x = transactions
    lap_y = []
    start = True
    while len(lap_y) != 1:
        if start:
            start = False
        else:
            lap_x = lap_y
            lap_y = []

        if (len(lap_x)%2 == 0):
            for i in range(0,len(lap_x)-1,2):
                linked_hashes = lap_x[i] + lap_x[i+1]
                lap_y.append(hashlib.sha256(linked_hashes.encode()).hexdigest())
        else:
            for i in range(0,len(lap_x)-2,2):
                linked_hashes = lap_x[i] + lap_x[i+1]
                lap_y.append(hashlib.sha256(linked_hashes.encode()).hexdigest())
            lap_y.append(lap_x[-1])
    merkle_root = lap_y[0]
    return merkle_root

def api_error():
    print('\n An error ocurred. Seems that the API is not working properly')
    quit()

ip_address = ''
port = 0

if len(sys.argv) == 4:
    ip_address = sys.argv[1]
    port = sys.argv[2]

elif len(sys.argv) == 5:
    print('\n [*] Choosing the node to mine')

    # getting the chain length from each node
    nodes = []

    try:
        chain = requests.get(f'http://{sys.argv[1]}:{sys.argv[2]}/api/chain', timeout=1).json()
        nodes.append({
            'ip_address': sys.argv[1],
            'port': sys.argv[2],
            'length': len(chain),
        })
    except:
        pass # ignore the node

    try:
        r_nodes = requests.get(f'http://{sys.argv[1]}:{sys.argv[2]}/api/nodes', timeout=1)
        if r_nodes.status_code != 200:
            api_error()
    except:
        api_error()
        
    for node in r_nodes.json():
        try:
            chain = requests.get(f"http://{node['ip_address']}:{str(node['port'])}/api/chain", timeout=1).json()
            nodes.append({
                'ip_address': node['ip_address'],
                'port': node['port'],
                'length': len(chain),
            })
        except:
            pass # ignore the node

    # getting the node with the longest chain
    node = sorted(nodes, key=lambda k: k['length'], reverse=True)[0]
    ip_address = node['ip_address']
    port = node['port']

    print(f" --> http://{ip_address}:{port}")

else:
    print('\n [*] Usage: py miner.py <ip-node> <port> <address> [-d]\n')
    print("     [+] If '-d' is passed, the node will be used to get the rest of the nodes and then choose one, not to mine directly.")
    print("     [-] If not, the node will be used to mine directly.\n")
    quit()


print('\n [*] Getting the height and previous_hash')

r = requests.get(f'http://{ip_address}:{port}/api/chain')
if r.status_code != 200:
    api_error()
last_block = r.json()
height = (int(last_block[-1]['height']) + 1)
previous_hash = last_block[-1]['block_hash']


print(' [*] Getting the coinbase_tx')

url = str(f'http://{ip_address}:{port}/api/coinbase_tx/')
data = {
    'address':sys.argv[3]
}
r = requests.post(url, data=data)
if r.status_code != 200:
    api_error()
coinbase_tx = r.json()
transactions = []
transactions.append({
    'tx_hash': coinbase_tx['tx_hash'],
    'sender': coinbase_tx['sender'],
    'receiver': coinbase_tx['receiver'],
    'amount': coinbase_tx['amount'],
    'fee': coinbase_tx['fee'],
    'sender_public_key': coinbase_tx['sender_public_key'],
    'timestamp': coinbase_tx['timestamp'],
    'signature': coinbase_tx['signature'],
})


print(' [*] Collecting mempool transactions')

r = requests.get(f'http://{ip_address}:{port}/api/mempool')
if r.status_code != 200:
    api_error()
mempool_tx = r.json()
contador = 0
total_fee = float(0.0)
for mem_tx in mempool_tx:
    if contador < 6:
        r = requests.get(f"http://{ip_address}:{port}/api/tx/{mem_tx['tx_hash']}")
        if r.status_code != 200:
            api_error()
        tx = r.json()
        transactions.append({
            'tx_hash': tx['tx_hash'],
            'sender': tx['sender'],
            'receiver': tx['receiver'],
            'amount': tx['amount'],
            'fee': tx['fee'],
            'sender_public_key': tx['sender_public_key'],
            'timestamp': tx['timestamp'],
            'signature': tx['signature'],
        })
        contador += 1
        total_fee += float(tx['fee'])
        

print(' [*] Getting the fee_tx')

if total_fee > 0.0:
    url = str(f'http://{ip_address}:{port}/api/fee_tx/')
    data = {
        'address': sys.argv[3],
        'total_fee': float('%.4f' % total_fee)
    }
    r = requests.post(url, data=data)
    if r.status_code != 200:
        api_error()
    fee_tx = r.json()
    transactions.append({
        'tx_hash': fee_tx['tx_hash'],
        'sender': fee_tx['sender'],
        'receiver': fee_tx['receiver'],
        'amount': fee_tx['amount'],
        'fee': fee_tx['fee'],
        'sender_public_key': fee_tx['sender_public_key'],
        'timestamp': fee_tx['timestamp'],
        'signature': fee_tx['signature'],
    })


print(' [*] Calculating the merkle_root')

hashes = []
for tx in transactions:
    hashes.append(tx['tx_hash'])
merkle_root = get_merkle_root(hashes)


print(' [*] Mining the block')

nonce = 0
block_hash = '-'
timestamp = datetime.now()
str_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
while block_hash[:5] != '00000':
    nonce += 1
    string = str(height) + str(nonce) + str_timestamp + previous_hash + merkle_root
    block_hash = hashlib.sha256(string.encode()).hexdigest()


print(' [*] Sending it')

url = str(f'http://{ip_address}:{port}/api/chain/')
data = {
    'block_hash': block_hash,
    'height': height,
    'nonce': nonce,
    'timestamp': timestamp,
    'previous_hash': previous_hash,
    'merkle_root': merkle_root,
    'transactions': base64.b64encode(str(transactions).encode()).decode(),
}
r = requests.post(url, data=data)
if r.status_code == 201:
    print('\n [*] Block mined succesfully!')
else:
    print('\n Invalid block, try again.')