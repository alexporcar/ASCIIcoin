from django.db.models import F
from django.http import HttpResponse
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from main.models import Transaction, Mempool, Block_header, Block_transaction, Node
from main.api.serializers import TransactionSerializer, MempoolSerializer, Block_headerSerializer, NodeSerializer, ChainSerializer
from datetime import datetime
import requests

@api_view(['GET', 'POST'])
def nodes(request):
    if request.method == 'GET':
        nodes = Node.objects.all()
        serializer = NodeSerializer(nodes, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = NodeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'DELETE'])
def node(request, ip_address):
    try:
        node = Node.objects.get(ip_address=ip_address)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    if request.method == 'GET':
        serializer = NodeSerializer(node)
        return Response(serializer.data)
    
    elif request.method == 'DELETE':
        node.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['GET', 'POST'])
def chain(request):
    if request.method == 'GET':
        blocks = Block_header.objects.all()
        serializer = Block_headerSerializer(blocks, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        serializer = ChainSerializer(data=request.data)
        if serializer.is_valid():
            if len(Block_header.objects.filter(block_hash=request.data['block_hash'])) == 0:
                if serializer.create(request.data):
                    # sharing the block with the rest of nodes
                    for node in Node.objects.all():
                        try:
                            url = f'http://{node.ip_address}:{node.port}/api/store_block/'
                            data = {
                                'block_hash': request.data['block_hash'],
                                'height': int(request.data['height']),
                                'nonce': int(request.data['nonce']),
                                'timestamp': datetime.strptime(request.data['timestamp'], "%Y-%m-%d %H:%M:%S.%f"),
                                'previous_hash': request.data['previous_hash'],
                                'merkle_root': request.data['merkle_root'],
                                'transactions': request.data['transactions'],
                            }
                            r = requests.post(url, data=data, timeout=1)
                            # we don't need to check the status code received
                        except:
                            pass # ignore the node
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def store_block(request):
    if request.method == 'POST':
        serializer = ChainSerializer(data=request.data)
        if serializer.is_valid():
            if len(Block_header.objects.filter(block_hash=request.data['block_hash'])) == 0:
                if serializer.create(request.data):
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                else:
                    return HttpResponse(status=418)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def store_transaction(request):
    if request.method == 'POST':
        serializer = TransactionSerializer(data=request.data)
        if serializer.is_valid():
            if len(Transaction.objects.filter(tx_hash=request.data['tx_hash'])) == 0:
                if serializer.create(request.data):
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                else:
                    return HttpResponse(status=418)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def last_block(request):
    try:
        block = Block_header.objects.all().order_by('-height')[0]
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)
        
    serializer = Block_headerSerializer(block)
    return Response(serializer.data)

@api_view(['GET'])
def block(request, block_hash):
    try:
        block = Block_header.objects.get(block_hash=block_hash)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = Block_headerSerializer(block)
    return Response(serializer.data)

@api_view(['GET'])
def tx(request, tx_hash):
    try:
        tx = Transaction.objects.get(tx_hash=tx_hash)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = TransactionSerializer(tx)
    return Response(serializer.data)

@api_view(['GET'])
def tx_block(request, block_hash):
    try:
        tx = Block_transaction.objects.filter(block_hash=block_hash).order_by('index').values('tx_hash', sender=F('tx_hash__sender'), receiver=F('tx_hash__receiver'), amount=F('tx_hash__amount'), fee=F('tx_hash__fee'), sender_public_key=F('tx_hash__sender_public_key'), timestamp=F('tx_hash__timestamp'), signature=F('tx_hash__signature'))
    except:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = TransactionSerializer(tx, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def tx_address(request, address):
    tx = Transaction.objects.filter(sender=address)
    serializer = TransactionSerializer(tx, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def mempool(request):
    Mempool.objects.check_mempool()
    tx = Mempool.objects.all().order_by('-fee', '-timestamp')
    serializer = MempoolSerializer(tx, many=True)
    return Response(serializer.data)

@api_view(['POST'])
def coinbase_tx(request):
    tx = Transaction.objects.create_coinbase_tx(request.data['address'])
    if tx == False:
        return Response('An error ocurred')
    serializer = TransactionSerializer(tx)
    return Response(serializer.data)

@api_view(['POST'])
def fee_tx(request):
    tx = Transaction.objects.create_fee_tx(request.data['address'], float(request.data['total_fee']))
    if tx == False:
        return Response('An error ocurred')
    serializer = TransactionSerializer(tx)
    return Response(serializer.data)