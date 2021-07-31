from django.db import IntegrityError, transaction
from django.test import TestCase
from main.models import MyUser, Transaction, Block_header, Mempool
from datetime import datetime
import main.utils as utils, hashlib

class GeneralTestCase(TestCase):
    with transaction.atomic():
        try:
            # creating users
            admin = MyUser.objects.create_superuser('admin@gmail.com', 'superpa$$word')
            bob = MyUser.objects.create_user('bob@gmail.com', 'passwd1234')
            alice = MyUser.objects.create_user('alice@gmail.com', 'passwd1234')
            adolfo = MyUser.objects.create_user('adolfo@gmail.com', 'passwd1234')
            teresa = MyUser.objects.create_user('teresa@gmail.com', 'passwd1234')
            print('\n[*] Users created succesfully')
            # starting the chain
            Block_header.objects.create_genesis_block(str(admin.address))
            print('\n[*] Genesis block created succesfully')

            # creating transactions
            if not Transaction.objects.create_transaction(str(admin.address), str(adolfo.address), 12, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('\n[*] Transaction #1 completed succesfully')
            if not Transaction.objects.create_transaction(str(admin.address), str(bob.address), 40, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('[*] Transaction #2 completed succesfully')
            if not Transaction.objects.create_transaction(str(admin.address), str(alice.address), 10, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('[*] Transaction #3 completed succesfully')
            if not Transaction.objects.create_transaction(str(admin.address), str(teresa.address), 15, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('[*] Transaction #4 completed succesfully')
            if not Transaction.objects.create_transaction(str(admin.address), str(bob.address), 23.1986, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('[*] Transaction #5 completed succesfully')

            # coinbase transaction
            coinbase_tx = Transaction.objects.create_coinbase_tx(str(admin.address))
            tx_to_send = []
            tx_to_send.append({
                'tx_hash': coinbase_tx.tx_hash,
                'sender': coinbase_tx.sender, 
                'receiver': coinbase_tx.receiver, 
                'amount': coinbase_tx.amount, 
                'fee': coinbase_tx.fee, 
                'sender_public_key': coinbase_tx.sender_public_key, 
                'timestamp': coinbase_tx.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'), 
                'signature': coinbase_tx.signature
            })

            # taking transactions from the mempool
            Mempool.objects.check_mempool()
            transactions = Mempool.objects.all()
            total_fee = 0
            for tx in transactions:
                tx_obj = Transaction.objects.get(tx_hash=tx.tx_hash)
                tx_to_send.append({
                    'tx_hash': tx_obj.tx_hash,
                    'sender': tx_obj.sender, 
                    'receiver': tx_obj.receiver, 
                    'amount': tx_obj.amount, 
                    'fee': tx_obj.fee, 
                    'sender_public_key': tx_obj.sender_public_key, 
                    'timestamp': tx_obj.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'), 
                    'signature': tx_obj.signature
                })
                total_fee += tx_obj.fee
            
            # fee transaction
            fee_tx = Transaction.objects.create_fee_tx(str(admin.address), float('%.4f' % total_fee))
            tx_to_send.append({
                'tx_hash': fee_tx.tx_hash,
                'sender': fee_tx.sender, 
                'receiver': fee_tx.receiver, 
                'amount': fee_tx.amount, 
                'fee': fee_tx.fee, 
                'sender_public_key': fee_tx.sender_public_key, 
                'timestamp': fee_tx.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'), 
                'signature': fee_tx.signature
            })

            # getting the merkle root
            hashes = []
            for tx in tx_to_send:
                hashes.append(tx['tx_hash'])
            merkle_root = utils.get_merkle_root(hashes)

            last_block = Block_header.objects.all().order_by('-height')[0]
            previous_hash = last_block.block_hash
            height = last_block.height + 1

            # proof of work
            nonce = 0
            block_hash = '-'
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            while block_hash[:5] != '00000':
                nonce += 1
                string = str(height) + str(nonce) + timestamp + previous_hash + merkle_root
                block_hash = hashlib.sha256(string.encode()).hexdigest()
                
            block = Block_header.objects.create_block(block_hash, height, nonce, timestamp, previous_hash, merkle_root, tx_to_send)
            if not block:
                raise IntegrityError
            print('\n[*] Block minned succesfully')

            if not Transaction.objects.create_transaction(str(teresa.address), str(bob.address), 0.14, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('\n[*] Transaction #6 completed succesfully')
            if not Transaction.objects.create_transaction(str(admin.address), str(alice.address), 25, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('[*] Transaction #7 completed succesfully')
            if not Transaction.objects.create_transaction(str(alice.address), str(adolfo.address), 1.0003, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #8 completed succesfully')
            if not Transaction.objects.create_transaction(str(alice.address), str(bob.address), 2.9878, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #9 completed succesfully')
            if not Transaction.objects.create_transaction(str(alice.address), str(teresa.address), 1, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #10 completed succesfully')
            if not Transaction.objects.create_transaction(str(adolfo.address), str(teresa.address), 1.3245, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #11 completed succesfully')
            if not Transaction.objects.create_transaction(str(admin.address), str(bob.address), 0.14, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('[*] Transaction #12 completed succesfully')
            if not Transaction.objects.create_transaction(str(teresa.address), str(bob.address), 0.14, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #13 completed succesfully')
            if not Transaction.objects.create_transaction(str(admin.address), str(alice.address), 0.12, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('[*] Transaction #14 completed succesfully')
            if not Transaction.objects.create_transaction(str(alice.address), str(adolfo.address), 1.0003, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #15 completed succesfully')
            if not Transaction.objects.create_transaction(str(alice.address), str(bob.address), 2.9878, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #16 completed succesfully')
            if not Transaction.objects.create_transaction(str(alice.address), str(teresa.address), 1, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #17 completed succesfully')
            if not Transaction.objects.create_transaction(str(adolfo.address), str(bob.address), 1.3245, 0.0001, 'passwd1234'):
                raise IntegrityError
            print('[*] Transaction #18 completed succesfully')
            if not Transaction.objects.create_transaction(str(admin.address), str(bob.address), 0.14, 0.0001, 'superpa$$word'):
                raise IntegrityError
            print('[*] Transaction #19 completed succesfully')

        except:
            raise IntegrityError