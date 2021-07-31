from main.models import MyUser, Wallet, Transaction, Mempool, Block_header, Block_transaction, Node
from rest_framework import serializers
import base64, json

class TimestampField(serializers.ReadOnlyField):
    def to_representation(self, value):
        return value.strftime('%Y-%m-%d %H:%M:%S.%f')

class MyUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ['email', 'address', 'is_admin', 'is_active']

class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['address', 'encrypted_private_key', 'public_key']

class TransactionSerializer(serializers.ModelSerializer):
    timestamp = TimestampField()

    def create(self, data):
        tx = Transaction.objects.create_raw_transaction(
            tx_hash = data['tx_hash'],
            sender = data['sender'],
            receiver = data['receiver'],
            amount = data['amount'],
            fee = data['fee'],
            sender_public_key = data['sender_public_key'],
            timestamp = data['timestamp'],
            signature = data['signature'],
            mempool = True,
        )
        if tx == False:
            return False
        else:
            return True

    class Meta:
        model = Transaction
        fields = ['tx_hash', 'sender', 'receiver', 'amount', 'fee', 'sender_public_key', 'timestamp', 'signature']

class MempoolSerializer(serializers.ModelSerializer):
    timestamp = TimestampField()

    class Meta:
        model = Mempool
        fields = ['tx_hash', 'sender', 'fee', 'timestamp']

class Block_headerSerializer(serializers.ModelSerializer):
    timestamp = TimestampField()

    class Meta:
        model = Block_header
        fields = ['block_hash', 'height', 'nonce', 'timestamp', 'previous_hash', 'merkle_root']

class ChainSerializer(serializers.ModelSerializer):
    transactions = serializers.CharField()

    def create(self, data):
        block = Block_header.objects.create_block(
            block_hash = data['block_hash'],
            height = data['height'],
            nonce = data['nonce'],
            timestamp = data['timestamp'],
            previous_hash = data['previous_hash'],
            merkle_root = data['merkle_root'],
            transactions = json.loads(base64.b64decode(data['transactions']).decode().replace('\'', '\"')),
        )
        if block == False:
            return False
        else:
            return True
    
    class Meta:
        model = Block_header
        fields = ['block_hash', 'height', 'nonce', 'timestamp', 'previous_hash', 'merkle_root', 'transactions']

class Block_transactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Block_transaction
        fields = ['tx_hash', 'index', 'block_hash']

class NodeSerializer(serializers.ModelSerializer):
    def validate(self, data):
        # checking the address
        ip_address = data['ip_address']
        x = ip_address.split('.')
        for i in range(0,4):
            if int(x[i]) < 0 or int(x[i]) > 255:
                raise serializers.ValidationError('The ip address is invalid')

        # checking the port
        port = data['port']
        if type(port) == int:
            if port < 0 or port > 65535:
                raise serializers.ValidationError('The port number is invalid')
        
        return data

    class Meta:
        model = Node
        fields = ['ip_address', 'port']