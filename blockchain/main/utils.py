from cryptography.fernet import Fernet
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from datetime import datetime
import hashlib, base64, base58

def encrypt(password, data):
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode()).decode()
    return encrypted_data

def decrypt(password, encrypted_data):
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    cipher = Fernet(key)
    data = cipher.decrypt(encrypted_data.encode()).decode()
    return data

def get_address(pubKey_b64):
    public_key = base64.b64decode(pubKey_b64)
    ripemd160 = hashlib.new('ripemd160')
    pubkey_hashed = hashlib.sha256(public_key).digest()
    ripemd160.update(pubkey_hashed)
    address = "00" + ripemd160.hexdigest() # '00' indicates the version of the network
    first_hash = hashlib.sha256(address.encode())
    checksum = hashlib.sha256(first_hash.digest()).hexdigest()
    address = address + checksum[:8] # adds the first 4 bytes of the checksum to the address
    return base58.b58encode(bytes.fromhex(address)).decode()

def key_pair_generator():
    # private key
    private_key = SigningKey.generate(curve=SECP256k1)
    privKey_b64 = base64.b64encode(private_key.to_string()).decode()
    # public key
    public_key = private_key.verifying_key
    pubKey_b64 = base64.b64encode(public_key.to_string()).decode()
    # address
    address = get_address(pubKey_b64)
    return privKey_b64, pubKey_b64, address

def sign(private_key_b64, data):
    private_key_string = base64.b64decode(private_key_b64)
    private_key = SigningKey.from_string(private_key_string, curve=SECP256k1)
    signature = private_key.sign(data.encode())
    return base64.b64encode(signature).decode()

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

def check_raw_transaction(tx_hash, sender, receiver, amount, fee, sender_public_key, timestamp, signature, now, check_balance):
    if type(now) != bool or type(check_balance) != bool:
        return False

    # checking strings parameters
    if len(tx_hash) != 64 or len(sender) < 24 or len(sender) > 36 or len(receiver) > 36 or len(receiver) < 24 or len(sender_public_key) != 88 or type(timestamp) != datetime or len(signature) != 88:
        return False
    
    # checking the amount and fee
    if (type(amount) == int or type(amount) == float) and (type(fee) == int or type(fee) == float):
        if amount <= 0 or fee < 0:
            return False
    else:
        return False
    
    # checking the hash
    data = sender + receiver + str(float(amount)) + str(float(fee)) + sender_public_key + timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
    hash_check = hashlib.sha256(data.encode()).hexdigest()
    if tx_hash != hash_check:
        return False
        
    # checking the signature
    public_key_string = base64.b64decode(sender_public_key)
    public_key = VerifyingKey.from_string(public_key_string, curve=SECP256k1)
    signature = base64.b64decode(signature)
    if not public_key.verify(signature, tx_hash.encode()):
        return False
        
    # checking the balance
    from main.models import Transaction # needs to be here
    if check_balance:
        if now:
            balance_check = Transaction.objects.check_balance(sender, datetime.now())
        else:
            balance_check = Transaction.objects.check_balance(sender, timestamp)
        if balance_check < float('%.4f' % (float(amount) + float(fee))):
            return False
    
    return True

def check_block(block_hash, height, nonce, timestamp, previous_hash, merkle_root, transactions):
    # checking the strings
    if len(block_hash) != 64 or len(previous_hash) != 64 or len(merkle_root) != 64:
        return False
    
    if height == 1 and previous_hash != 'eab06ee07b5534d39b0323bb5e2fee864b5617765ab82878482c1dbf1d035b88':
        return False
    
    # checking the timestamp format
    try:
        timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
    except:
        return False

    # checking the hash
    if block_hash[:5] != '00000':
        return False
    data = str(height) + str(nonce) + timestamp.strftime('%Y-%m-%d %H:%M:%S.%f') + previous_hash + merkle_root
    hash_check = hashlib.sha256(data.encode()).hexdigest()
    if block_hash != hash_check:
        return False

    # checking the merkle root
    hashes = []
    for tx in transactions:
        hashes.append(tx['tx_hash'])
    merkle_check = get_merkle_root(hashes)
    if merkle_root != merkle_check:
        return False
    
    # checking the coinbase transaction
    coinbase_tx = list(transactions)[0]
    if float(coinbase_tx['amount']) != 200.0:
        return False
    data = coinbase_tx['receiver'] + str(200.0) + str(0.0) + coinbase_tx['timestamp']
    tx_hash = hashlib.sha256(data.encode()).hexdigest()
    if tx_hash != coinbase_tx['tx_hash']:
        return False

    # checking the fee transaction
    if len(transactions) > 2:
        fee_check = 0.0
        for tx in transactions:
            fee_check += float(tx['fee'])
        fee_tx = list(transactions)[-1]
        if float(fee_tx['amount']) != float('%.4f' % fee_check) or float(fee_tx['amount']) == float(0.0):
            return False
        data = fee_tx['receiver'] + str(float(fee_tx['amount'])) + str(0.0) + fee_tx['timestamp']
        tx_hash = hashlib.sha256(data.encode()).hexdigest()
        if tx_hash != fee_tx['tx_hash']:
            return False
            
    # checking all other transactions
    for tx in transactions:
        if list(transactions)[0]['tx_hash'] == tx['tx_hash'] or list(transactions)[-1]['tx_hash'] == tx['tx_hash']:
            continue
        if not check_raw_transaction(tx['tx_hash'], tx['sender'], tx['receiver'], float(tx['amount']), float(tx['fee']), tx['sender_public_key'], datetime.strptime(tx['timestamp'], "%Y-%m-%d %H:%M:%S.%f"), tx['signature'], now=False, check_balance=False):
            return False
    
    return True

def check_balances(transactions, balances):
    for tx in transactions:
        if tx['receiver'] in balances:
            balances[tx['receiver']] = float(balances[tx['receiver']]) + float(tx['amount'])
        else:
            balances[tx['receiver']] = float(tx['amount'])

        if tx['sender'] == '':
            continue
        
        if tx['sender'] in balances:
            balances[tx['sender']] = float(balances[tx['sender']]) - float(tx['amount']) - float(tx['fee'])
        else:
            balances[tx['sender']] = - float(tx['amount']) - float(tx['fee'])
    
    return balances