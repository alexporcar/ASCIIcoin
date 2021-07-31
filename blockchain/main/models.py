from django.db import models, IntegrityError, transaction
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from datetime import datetime
from ecdsa import VerifyingKey, SECP256k1
import main.utils as utils, base64, hashlib

# Managers

class MyUserManager(BaseUserManager):
    def create_user(self, email, password):
        # checking if the email is already used
        try:
            if MyUser.objects.get(email=email):
                return False
        except:
            pass

        # wallet
        privKey_b64, pubKey_b64, address = utils.key_pair_generator()
        ciphered_key = utils.encrypt(password, privKey_b64)

        with transaction.atomic():
            try:
                wallet = Wallet(
                    address = address,
                    encrypted_private_key = ciphered_key,
                    public_key = pubKey_b64,
                )
                wallet.save(using=self._db)

                # user
                user = self.model(
                    email = self.normalize_email(email),
                    address = wallet,
                )
                user.set_password(password)
                user.save(using=self._db)
                return user
            except:
                raise IntegrityError

    def create_superuser(self, email, password):
        user = self.create_user(
            email = email,
            password = password,
        )
        if not user:
            return False
        user.is_admin = True
        user.save(using=self._db)
        return user

class TransactionManager(models.Manager):
    def create_transaction(self, sender, receiver, amount, fee, password):
        # checking the addresses
        if len(sender) < 24 or len(sender) > 36 or len(receiver) > 36 or len(receiver) < 24:
            raise ValueError('The receiver address is not correct.')
        
        # checking the amount and fee
        if (type(amount) == int or type(amount) == float) and (type(fee) == int or type(fee) == float):
            if amount <= 0 or fee < 0:
                raise ValueError('Invalid quantities.')
        else:
            raise ValueError('Invalid quantities.')
            
        # checking the balance
        timestamp = datetime.now()
        balance = self.check_balance(sender, timestamp)
        if float(balance) < float('%.4f' % (float(amount) + float(fee))):
            raise ValueError('Your balance cannot support this transaction.')
            
        try:
            sender_wallet = Wallet.objects.get(address=sender)
            encrypted_private_key = sender_wallet.encrypted_private_key
            private_key_b64 = utils.decrypt(password, encrypted_private_key)
        except:
            raise ValueError('Incorrect password')

        tx = Transaction(
            sender = sender,
            receiver = receiver,
            amount = float(amount),
            fee = float(fee),
            sender_public_key = sender_wallet.public_key,
            timestamp = timestamp,
        )
        data = sender + receiver + str(float(amount)) + str(float(fee)) + tx.sender_public_key + tx.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        tx_hash = hashlib.sha256(data.encode()).hexdigest()
        tx.tx_hash = tx_hash
        tx.signature = utils.sign(private_key_b64, tx_hash)
        
        with transaction.atomic():
            tx.save(using=self._db)
            if Mempool.objects.add_transaction(tx): # adding the new transaction to the mempool
                return tx
            else:
                raise IntegrityError
    
    def create_raw_transaction(self, tx_hash, sender, receiver, amount, fee, sender_public_key, timestamp, signature, mempool):
        if type(mempool) != bool:
            raise ValueError("'mempool' has to be a boolean field")
        
        # checking the timestamp format
        try:
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
        except:
            return False

        # checking the transaction
        if not utils.check_raw_transaction(tx_hash, sender, receiver, float(amount), float(fee), sender_public_key, timestamp, signature, now=True, check_balance=True):
            return False
        
        tx = Transaction(
            tx_hash = tx_hash,
            sender = sender,
            receiver = receiver,
            amount = float(amount),
            fee = float(fee),
            sender_public_key = sender_public_key,
            timestamp = timestamp,
            signature = signature,
        )
        if mempool:
            with transaction.atomic():
                tx.save(using=self._db)
                if not Mempool.objects.add_transaction(tx): # adding the new transaction to the mempool
                    raise IntegrityError
        return tx

    def create_coinbase_tx(self, node_address):
        # checking the address
        if len(node_address) > 36:
            return False
        
        coinbase_tx = Transaction(
            sender = '',
            receiver = node_address,
            amount = float(200),
            fee = float(0),
            sender_public_key = '',
            timestamp = datetime.now(),
            signature = '',
        )
        data = node_address + str(200.0) + str(0.0) + coinbase_tx.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        tx_hash = hashlib.sha256(data.encode()).hexdigest()
        coinbase_tx.tx_hash = tx_hash

        return coinbase_tx
    
    def create_fee_tx(self, node_address, total_fee):
        if len(node_address) > 36 or float(total_fee) < 0:
            return False

        fee_tx = Transaction(
            sender = '',
            receiver = node_address,
            amount = float(total_fee),
            fee = float(0.0),
            sender_public_key = '',
            timestamp = datetime.now(),
            signature = '',
        )
        data = node_address + str(float('%.4f' % total_fee)) + str(0.0) + fee_tx.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        tx_hash = hashlib.sha256(data.encode()).hexdigest()
        fee_tx.tx_hash = tx_hash
        
        return fee_tx

    def check_transaction(self, tx):
        # coinbase and fee transactions
        if tx.sender == '':
            data = tx.receiver + str(float(tx.amount)) + str(0.0) + tx.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
            tx_hash = hashlib.sha256(data.encode()).hexdigest()
            if tx_hash != tx.tx_hash:
                return False
            return True
        
        # checking the hash
        data = tx.sender + tx.receiver + str(float(tx.amount)) + str(float(tx.fee)) + tx.sender_public_key + tx.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        if not tx.tx_hash == hashlib.sha256(data.encode()).hexdigest():
            return False
        
        # checking the signature
        public_key_string = base64.b64decode(tx.sender_public_key)
        public_key = VerifyingKey.from_string(public_key_string, curve=SECP256k1)
        signature = base64.b64decode(tx.signature)
        if not public_key.verify(signature, tx.tx_hash.encode()):
            return False

        # checking sender balance
        balance_check = self.check_balance(tx.sender, tx.timestamp)
        if (tx.amount + tx.fee) > balance_check:
            return False
        
        return True

    def check_balance(slef, address, timestamp):
        instances = Block_transaction.objects.all()
        balance = float(0.0)

        if len(instances) != 0:
            for instance in instances:
                try:
                    transaction = Transaction.objects.get(tx_hash=instance.tx_hash)
                    if transaction.timestamp < timestamp:
                        if transaction.sender == address:
                            balance -= float(transaction.amount + transaction.fee)
                        if transaction.receiver == address:
                            balance += float(transaction.amount)
                except:
                    raise ValueError('Something went wrong. A confirmed transaction must be in the chain.')

        return float('%.4f' % balance)
    
    def clean_transactions(self):
        delete = Mempool.objects.check_mempool()

        confirmed = []
        for tx in Block_transaction.objects.filter():
            confirmed.append(tx.tx_hash.tx_hash)

        unconfirmed = []
        for tx in Mempool.objects.filter():
            unconfirmed.append(tx.tx_hash.tx_hash)

        for tx in Transaction.objects.filter():
            if (tx.tx_hash in confirmed) and (tx.tx_hash in unconfirmed):
                Mempool.objects.get(tx_hash=tx.tx_hash).delete()
                continue
            elif (tx.tx_hash in confirmed) or (tx.tx_hash in unconfirmed):
                continue
            else:
                tx.delete()
                delete = True

        return delete

class MempoolManager(models.Manager):
    def add_transaction(self, tx):
        # avoids coinbase or fee transactions
        if tx.sender == '':
            return False

        tx_mempool = Mempool(
            tx_hash = tx,
            sender = tx.sender,
            fee = tx.fee,
            timestamp = tx.timestamp,
        )
        tx_mempool.save(using=self._db)
        return True

    def check_mempool(self):
        delete = False
        for transaction in Mempool.objects.all():
            tx = Transaction.objects.get(tx_hash=transaction.tx_hash)
            if tx.sender == '':
                transaction.delete()
                tx.delete()
                delete = True

            # checking sender balance
            balance_check = Transaction.objects.check_balance(tx.sender, datetime.now())
            if (tx.amount + tx.fee) > balance_check:
                transaction.delete()
                tx.delete()
                delete = True

        return delete

class Block_transactionManager(models.Manager):
    def create_instance(self, tx, index, block):
        if type(index) != int:
            return False
            
        instance = Block_transaction(
            tx_hash = tx,
            index = index,
            block_hash = block,
        )
        instance.save(using=self._db)
        return instance

class Block_headerManager(models.Manager):
    def create_block(self, block_hash, height, nonce, timestamp, previous_hash, merkle_root, transactions):
        # checking the strings
        if len(block_hash) != 64 or len(previous_hash) != 64 or len(merkle_root) != 64:
            return False
        
        # checking the timestamp format
        try:
            timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
        except:
            return False

        if height != 1:
            # checking the height
            try:
                previous_block = Block_header.objects.get(block_hash=previous_hash)
                if int(previous_block.height) != (int(height)-1):
                    return False
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
        merkle_check = utils.get_merkle_root(hashes)
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
        
        # checking mempool for invalid transactions
        if Mempool.objects.check_mempool():
            return False

        with transaction.atomic():
            index = 0
            try:
                block = Block_header(
                    block_hash = block_hash,
                    height = height,
                    nonce = nonce,
                    timestamp = timestamp,
                    previous_hash = previous_hash,
                    merkle_root = merkle_root,
                )
                block.save(using=self._db)

                # checking all other transactions
                for tx in transactions:
                    # saving the coinbase and fee transaction
                    if list(transactions)[0]['tx_hash'] == tx['tx_hash'] or list(transactions)[-1]['tx_hash'] == tx['tx_hash']:
                        t = Transaction(
                            tx_hash = tx['tx_hash'],
                            sender = tx['sender'],
                            receiver = tx['receiver'],
                            amount = float(tx['amount']),
                            fee = float(tx['fee']),
                            sender_public_key = tx['sender_public_key'],
                            timestamp = datetime.strptime(tx['timestamp'], "%Y-%m-%d %H:%M:%S.%f"),
                            signature = tx['signature'],
                        )
                        t.save(using=self._db)

                    tx_query = Transaction.objects.filter(tx_hash=tx['tx_hash'])
                    if len(tx_query) != 0:
                        t = tx_query[0]
                        if not Block_transaction.objects.create_instance(t, index, block):
                            raise IntegrityError
                        if t.sender != '':
                            if len(Mempool.objects.filter(tx_hash=t.tx_hash)) != 0:
                                Mempool.objects.get(tx_hash=t).delete()
                    else:
                        t = Transaction.objects.create_raw_transaction(
                            tx_hash = tx['tx_hash'],
                            sender = tx['sender'],
                            receiver = tx['receiver'],
                            amount = tx['amount'],
                            fee = tx['fee'],
                            sender_public_key = tx['sender_public_key'],
                            timestamp = datetime.strptime(tx['timestamp'], "%Y-%m-%d %H:%M:%S.%f"),
                            signature = tx['signature'],
                            mempool = False,
                        )
                        if t == False or not Block_transaction.objects.create_instance(t, index, block):
                            raise IntegrityError
                    index += 1

                return block
            except:
                raise IntegrityError
    
    def add_block(self, block_hash, height, nonce, timestamp, previous_hash, merkle_root, transactions):
        # checking mempool for invalid transactions
        if Mempool.objects.check_mempool():
            return False
        
        with transaction.atomic():
            index = 0
            try:
                block = Block_header(
                    block_hash = block_hash,
                    height = height,
                    nonce = nonce,
                    timestamp = timestamp,
                    previous_hash = previous_hash,
                    merkle_root = merkle_root,
                )
                block.save(using=self._db)
                
                # checking all other transactions
                for tx in transactions:
                    # saving the coinbase and fee transaction
                    if len(Transaction.objects.filter(tx_hash=tx['tx_hash'])) == 0:
                        t = Transaction(
                            tx_hash = tx['tx_hash'],
                            sender = tx['sender'],
                            receiver = tx['receiver'],
                            amount = float(tx['amount']),
                            fee = float(tx['fee']),
                            sender_public_key = tx['sender_public_key'],
                            timestamp = datetime.strptime(tx['timestamp'], "%Y-%m-%d %H:%M:%S.%f"),
                            signature = tx['signature'],
                        )
                        t.save(using=self._db)
                        if t == False or not Block_transaction.objects.create_instance(t, index, block):
                            raise IntegrityError
                    else:
                        t = Transaction.objects.get(tx_hash=tx['tx_hash'])
                        if not Block_transaction.objects.create_instance(t, index, block):
                            raise IntegrityError
                        if len(Mempool.objects.filter(tx_hash=t.tx_hash)) != 0:
                            Mempool.objects.get(tx_hash=t.tx_hash).delete()

                    index += 1
                return block
            except:
                raise IntegrityError
    
    def create_genesis_block(self, node_address):
        # creating the coinbase transaction
        coinbase_tx = Transaction.objects.create_coinbase_tx(node_address)
        if coinbase_tx == False:
            return False
        
        # proof of work
        nonce = 0
        block_hash = '-'
        timestamp = datetime.now()
        str_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
        previous_hash = 'eab06ee07b5534d39b0323bb5e2fee864b5617765ab82878482c1dbf1d035b88' # 'TFG realizado por Alejandro Porcar Vidal - 2021' w/ SHA-256
        while block_hash[:5] != '00000':
            nonce += 1
            string = str(1) + str(nonce) + str_timestamp + previous_hash + coinbase_tx.tx_hash
            block_hash = hashlib.sha256(string.encode()).hexdigest()

        block = Block_header(
            block_hash = block_hash,
            height = 1,
            nonce = nonce,
            timestamp = timestamp,
            previous_hash = previous_hash,
            merkle_root = coinbase_tx.tx_hash,
        )
        with transaction.atomic():
            coinbase_tx.save(using=self._db)
            if not Block_transaction.objects.create_instance(coinbase_tx, 0, block):
                raise IntegrityError
            block.save(using=self._db)
            return block

    def check_block(self, block):
        # checking the previous_hash
        if block.height == 1 and block.previous_hash != 'eab06ee07b5534d39b0323bb5e2fee864b5617765ab82878482c1dbf1d035b88':
            return False
        elif block.height != 1 and block.previous_hash != Block_header.objects.filter(height=(block.height-1))[0].block_hash:
            return False
        
        # checking the hash
        if block.block_hash[:5] != '00000':
            return False
        data = str(block.height) + str(block.nonce) + block.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f") + block.previous_hash + block.merkle_root
        hash_data = hashlib.sha256(data.encode()).hexdigest()
        if block.block_hash != hash_data:
            return False
        
        # checking the transactions
        transactions = []
        instances = Block_transaction.objects.filter(block_hash=block.block_hash).order_by('index')
        if len(instances) == 0:
            return False
        for tx in instances:
            t = Transaction.objects.get(tx_hash=tx.tx_hash)
            if not Transaction.objects.check_transaction(t):
                return False
            transactions.append(t.tx_hash)
        
        # checking the merkle_root
        merkle_check = utils.get_merkle_root(transactions)
        if block.merkle_root == merkle_check:
            return True
        else:
            return False

    def invalidate_block(self, block):
        instances = Block_transaction.objects.filter(block_hash=block.block_hash)
        if len(instances) == 0:
            return False
        with transaction.atomic():
            for instance in instances:
                try:
                    tx = Transaction.objects.get(tx_hash=instance.tx_hash)
                    # removing the coinbase and fee transaction
                    if tx.sender == '':
                        instance.delete()
                        tx.delete()
                    else:
                        # putting the tx back into the mempool
                        if not Mempool.objects.add_transaction(tx):
                            raise IntegrityError
                        instance.delete()
                except:
                    raise IntegrityError
            
            # cleanning the mempool and removing the block
            Mempool.objects.check_mempool()
            block.delete()
            return True

    def check_chain(self):
        Transaction.objects.clean_transactions()
        for block in Block_header.objects.all().order_by('height'):
            if not Block_header.objects.check_block(block):
                for invalid_block in Block_header.objects.filter(height__gte=block.height):
                    Block_header.objects.invalidate_block(invalid_block)
                return False
        return True

# Models

class Wallet(models.Model):
    address = models.CharField(max_length=36, primary_key=True) # P2PKH format
    encrypted_private_key = models.CharField(max_length=140, unique=True) # ECDSA private key encrypted with AES-CBC and encoded in base64
    public_key = models.CharField(max_length=88, unique=True) # ECDSA public key in base64

    class Meta:
        verbose_name_plural = 'Wallets'

    def __str__(self):
        return self.address

class MyUser(AbstractBaseUser):
    email = models.EmailField(verbose_name='email', max_length=150, primary_key=True)
    address = models.OneToOneField(Wallet, on_delete=models.CASCADE, db_column='address') # P2PKH format
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    objects = MyUserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin
    
    def set_address(self, raw_password):
        privKey_b64, pubKey_b64, address = utils.key_pair_generator()
        ciphered_key = utils.encrypt(raw_password, privKey_b64)

        wallet = Wallet(
            address = address,
            encrypted_private_key = ciphered_key,
            public_key = pubKey_b64,
        )
        wallet.save()
        self.address = wallet

    def change_password(self, old_password, new_password):
        wallet = self.address
        try:
            private_key = utils.decrypt(old_password, wallet.encrypted_private_key)
        except:
            raise ValueError('Incorrect password')
        wallet.encrypted_private_key = utils.encrypt(new_password, private_key)
        wallet.save()
        self.set_password(new_password)
        self.save()

class Transaction(models.Model):
    tx_hash = models.CharField(max_length=64, primary_key=True) # SHA-256
    sender = models.CharField(max_length=36, blank=True) # P2PKH format
    receiver = models.CharField(max_length=36) # P2PKH format
    amount = models.DecimalField(max_digits=14, decimal_places=4)
    fee = models.DecimalField(max_digits=8, decimal_places=4, default=0)
    sender_public_key = models.CharField(max_length=88, blank=True) # ECDSA public key in base64
    timestamp = models.DateTimeField() # when hashing: "%d/%m/%Y %H:%M:%S.%f"
    signature = models.CharField(max_length=88, blank=True) # ECDSA signature in base64

    objects = TransactionManager()

    class Meta:
        verbose_name_plural = 'Transactions'

    def __str__(self):
        return self.tx_hash

class Mempool(models.Model):
    tx_hash = models.OneToOneField(Transaction, on_delete=models.DO_NOTHING, primary_key=True, db_column='tx_hash') # SHA-256
    sender = models.CharField(max_length=36) # P2PKH format
    fee = models.DecimalField(max_digits=8, decimal_places=4, default=0)
    timestamp = models.DateTimeField()

    objects = MempoolManager()

    class Meta:
        verbose_name_plural = 'Mempool'

    def __str__(self):
        return self.tx_hash

class Block_header(models.Model):
    block_hash = models.CharField(max_length=64, primary_key=True) # SHA-256
    height = models.PositiveIntegerField(unique=True)
    nonce = models.PositiveBigIntegerField()
    timestamp = models.DateTimeField() # when hashing: "%d/%m/%Y %H:%M:%S.%f"
    previous_hash = models.CharField(max_length=64) # SHA-256
    merkle_root = models.CharField(max_length=64) # SHA-256

    objects = Block_headerManager()

    class Meta:
        verbose_name_plural = 'Block_headers'

    def __str__(self):
        return self.block_hash

class Block_transaction(models.Model):
    tx_hash = models.OneToOneField(Transaction, on_delete=models.DO_NOTHING, primary_key=True, db_column='tx_hash') # SHA-256
    index = models.PositiveSmallIntegerField()
    block_hash = models.ForeignKey(Block_header, on_delete=models.DO_NOTHING, db_column='block_hash') # SHA-256

    objects = Block_transactionManager()

    class Meta:
        verbose_name_plural = 'Block_transactions'

    def __str__(self):
        return self.tx_hash.tx_hash

class Node(models.Model):
    ip_address = models.GenericIPAddressField(primary_key=True)
    port = models.PositiveIntegerField()

    class Meta:
        verbose_name_plural = 'Nodes'
    
    def __str__(cls):
        return str(f'http://{cls.ip_address}:{str(cls.port)}')