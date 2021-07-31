from django.shortcuts import render, redirect
from django.http import Http404, HttpResponseForbidden
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods, require_GET
from django.db import IntegrityError, transaction
from django.db.models import F, Q
from django.urls import reverse
from main.models import Transaction, Mempool, Block_transaction, Block_header, Node
from main.forms import MyUserCreationForm, SendTxForm, ConnectForm
from io import BytesIO
from datetime import datetime
import main.utils as utils, requests, qrcode, qrcode.image.svg, hashlib, base64

@require_GET
def home(request):
    return render(request, 'main/component/home.html')

@require_http_methods(['GET', 'POST'])
def register(request):
    context = {}
    if request.method == 'GET':
        if request.user.is_authenticated:
            return redirect('home')
        else:
            context['form'] = MyUserCreationForm
            return render(request, 'main/account/register.html', context=context)

    elif request.method == 'POST':
        form = MyUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            if user is not None:
                login(request, user)
                return redirect('home')

        context['form'] = form
        return render(request, 'main/account/register.html', context=context)

@login_required
@require_http_methods(['GET', 'POST'])
def export(request):
    context = {}
    if request.method == 'GET':
        return render(request, 'main/account/export.html', context=context)
    if request.method == 'POST':
        if request.user.check_password(request.POST['password']):
            context['allow'] = True
            context['private_key'] = utils.decrypt(request.POST['password'], request.user.address.encrypted_private_key)
            context['public_key'] = request.user.address.public_key
            context['address'] = request.user.address.address
            return render(request, 'main/account/export.html', context=context)
        else:
            context['error'] = 'Incorrect password.'
            return render(request, 'main/account/export.html', context=context)

@login_required
@require_GET
def account(request):
    context = {}
    address = request.user.address.address

    # creates a qr of the user's address
    factory = qrcode.image.svg.SvgImage
    img = qrcode.make(address, image_factory=factory, box_size=20)
    stream = BytesIO()
    img.save(stream)
    context['svg'] = stream.getvalue().decode()
    
    context['address'] = address
    context['transactions'] = Transaction.objects.filter(Q(sender=address) | Q(receiver=address)).order_by('-timestamp')
    
    tx_sent = tx_received = int(0)
    total_received = total_sent = balance = float(0.0)

    b_tx = []
    for t in Block_transaction.objects.all():
        b_tx.append(t.tx_hash.tx_hash)

    for tx in context['transactions']:
        if tx.tx_hash in b_tx:
            if tx.sender == address:
                tx_sent += 1
                total_sent += float(tx.amount + tx.fee)
            elif tx.receiver == address:
                tx_received += 1
                total_received += float(tx.amount)
    
    context['tx_sent'] = tx_sent
    context['tx_received'] = tx_received
    context['total_received'] = '%.4f' % total_received
    context['total_sent'] = '%.4f' % total_sent
    context['balance'] = '%.4f' % (total_received - total_sent)

    return render(request, 'main/account/address.html', context=context)

@login_required
@require_GET
def success(request):
    return render(request, 'main/component/success.html')

@require_GET
def explorer(request):
    context = {}
    context['chain'] = Block_header.objects.all().order_by('-height')[:5]
    context['transactions'] = Transaction.objects.all().order_by('-timestamp')[:5]
    return render(request, 'main/explorer/explorer.html', context=context)

@require_GET
def blocks(request):
    context = {}
    context['chain'] = Block_header.objects.all().order_by('-height')
    return render(request, 'main/explorer/chain.html', context=context)

@require_GET
def block(request, block_hash):
    try:
        block = Block_header.objects.get(block_hash=block_hash)
    except:
        raise Http404("The block does not exist")

    context = {}
    context['block_hash'] = block.block_hash
    context['previous_hash'] = block.previous_hash
    context['timestamp'] = block.timestamp.strftime("%d/%m/%Y %H:%M")
    context['height'] = block.height
    context['merkle_root'] = block.merkle_root
    context['nonce'] = block.nonce

    context['confirmations'] = Block_header.objects.all().order_by('-height')[0].height+1 - block.height
    context['number_transactions'] = len(Block_transaction.objects.filter(block_hash=block.block_hash))
    context['block_reward'] = Block_transaction.objects.filter(block_hash=block.block_hash, index=0).values('tx_hash__amount')[0]['tx_hash__amount']
    
    tx_volume = float(0.0)
    for tx in Block_transaction.objects.filter(block_hash=block.block_hash).values('tx_hash__amount'):
        tx_volume += float(tx['tx_hash__amount'])
    context['transaction_volume'] = '%.4f' % tx_volume

    fee_reward = float(0.0)
    for tx in Block_transaction.objects.filter(block_hash=block.block_hash).values('tx_hash__fee'):
        fee_reward += float(tx['tx_hash__fee'])
    context['fee_reward'] = '%.4f' % fee_reward

    context['transactions'] = tx = Block_transaction.objects.filter(block_hash=block_hash).order_by('index').values('tx_hash', sender=F('tx_hash__sender'), receiver=F('tx_hash__receiver'), amount=F('tx_hash__amount'), fee=F('tx_hash__fee'), sender_public_key=F('tx_hash__sender_public_key'), timestamp=F('tx_hash__timestamp'), signature=F('tx_hash__signature'))

    return render(request, 'main/explorer/block.html', context=context)

@require_GET
def transactions(request):
    context = {}
    context['transactions'] = Transaction.objects.all().order_by('-timestamp')

    return render(request, 'main/explorer/transactions.html', context=context)

@require_GET
def tx(request, tx_hash):
    try:
        tx = Transaction.objects.get(tx_hash=tx_hash)
    except:
        raise Http404("The transaction does not exist")

    context = {}
    context['tx_hash'] = tx.tx_hash
    context['sender'] = tx.sender
    context['receiver'] = tx.receiver
    context['amount'] = tx.amount
    context['fee'] = tx.fee
    context['sender_public_key'] = tx.sender_public_key
    context['timestamp'] = tx.timestamp.strftime("%d/%m/%Y %H:%M")
    context['signature'] = tx.signature

    try:
        instance = Block_transaction.objects.get(tx_hash=tx.tx_hash)
        context['confirmations'] = Block_header.objects.all().order_by('-height')[0].height+1 - Block_header.objects.get(block_hash=instance.block_hash).height
        context['status'] = 'Confirmed'
        context['included_in_block'] = instance.block_hash
    except:
        context['status'] = 'Unconfirmed'

    return render(request, 'main/explorer/tx.html', context=context)

@require_GET
def address(request, address):
    context = {}

    # creates a qr of the user's address
    factory = qrcode.image.svg.SvgImage
    img = qrcode.make(address, image_factory=factory, box_size=20)
    stream = BytesIO()
    img.save(stream)
    context['svg'] = stream.getvalue().decode()
    
    context['address'] = address
    context['transactions'] = Transaction.objects.filter(Q(sender=address) | Q(receiver=address)).order_by('-timestamp')
    
    tx_sent = tx_received = int(0)
    total_received = total_sent = balance = float(0.0)

    b_tx = []
    for t in Block_transaction.objects.all():
        b_tx.append(t.tx_hash.tx_hash)

    for tx in context['transactions']:
        if tx.tx_hash in b_tx:
            if tx.sender == address:
                tx_sent += 1
                total_sent += float(tx.amount + tx.fee)
            elif tx.receiver == address:
                tx_received += 1
                total_received += float(tx.amount)
    
    context['tx_sent'] = tx_sent
    context['tx_received'] = tx_received
    context['total_received'] = '%.4f' % total_received
    context['total_sent'] = '%.4f' % total_sent
    context['balance'] = '%.4f' % (total_received - total_sent)

    return render(request, 'main/explorer/address_details.html', context=context)

@login_required
@require_http_methods(['GET', 'POST'])
def send(request):
    context = {}
    context['form'] = SendTxForm

    if request.method == 'GET':
        return render(request, 'main/account/send.html', context=context)

    elif request.method == 'POST':
        form = SendTxForm(request.POST)

        if form.is_valid():
            receiver = request.POST['receiver']
            amount = request.POST['amount']
            fee = request.POST['fee']
            password = request.POST['password']
            try:
                tx = Transaction.objects.create_transaction(request.user.address.address, receiver, float(amount), float(fee), password)
            except ValueError as e:
                context['error'] = e
                return render(request, 'main/account/send.html', context=context)
            except:
                context['error'] = 'Something went wrong, try again.'
                return render(request, 'main/account/send.html', context=context)

            # sharing the block with the rest of nodes
            for node in Node.objects.all():
                try:
                    url = f'http://{node.ip_address}:{node.port}/api/store_transaction/'
                    data = {
                        'tx_hash': tx.tx_hash,
                        'sender': tx.sender,
                        'receiver': tx.receiver,
                        'amount': tx.amount,
                        'fee': tx.fee,
                        'sender_public_key': tx.sender_public_key,
                        'timestamp': tx.timestamp,
                        'signature': tx.signature,
                    }
                    r = requests.post(url, data=data, timeout=1)
                    # we don't need to check the status code received
                except:
                    pass # ignore the node

            context['tx_hash'] = tx.tx_hash
            return render(request, 'main/account/send.html', context=context)
        else:
            context['error'] = 'Invalid data, try again.'
            return render(request, 'main/account/send.html', context=context)

@login_required
@require_http_methods(['GET', 'POST'])
def connect(request):
    if not request.user.is_admin:
        return HttpResponseForbidden()

    context = {}
    context['form'] = ConnectForm

    if request.method == 'GET':
        return render(request, 'main/component/connect.html', context=context)

    elif request.method == 'POST':
        form = ConnectForm(request.POST)

        if form.is_valid():
            ip_address = request.POST['ip_address']
            port = request.POST['port']

            if ip_address == request.headers['Host'].split(':')[0]:
                context['error'] = "You can't connect to yourself."
                return render(request, 'main/component/connect.html', context=context)
            
            # getting the nodes
            try:
                nodes = requests.get(f'http://{ip_address}:{port}/api/nodes', timeout=1).json()
            except:
                context['error'] = f"The node http://{ip_address}:{port} doesn't belong to the ASCIIcoin network."
                return render(request, 'main/component/connect.html', context=context)

            url = str(f"http://{ip_address}:{port}/api/nodes/")
            data = {
                'ip_address': request.headers['Host'].split(':')[0],
                'port': request.headers['Host'].split(':')[1]
            }
            try:
                r = requests.post(url, data=data, timeout=1)
                if r.status_code == 201:
                    Node(ip_address=ip_address, port=port).save()
            except:
                pass # ignore the node

            # connecting to the network
            for node in nodes:
                try:
                    n = Node.objects.get(ip_address=node['ip_address'])
                except:
                    url = str(f"http://{node['ip_address']}:{node['port']}/api/nodes/")
                    data = {
                        'ip_address': request.headers['Host'].split(':')[0],
                        'port': request.headers['Host'].split(':')[1]
                    }
                    try:
                        r = requests.post(url, data=data, timeout=1)
                        if r.status_code == 201:
                            Node(ip_address=node['ip_address'], port=node['port']).save()
                    except:
                        pass # ignore the node
                        
            return render(request, 'main/component/success.html')
        else:
            context['form'] = form
            return render(request, 'main/component/connect.html', context=context)

    return render(request, 'main/component/connect.html', context=context)

@login_required
@require_GET
def sync(request):
    if not request.user.is_admin:
        return HttpResponseForbidden()
        
    # checking our chain
    Block_header.objects.check_chain()

    # collecting only the valid chains
    chains = []
    for node in Node.objects.all():
        try:
            # getting the chain
            chain = requests.get(f'http://{node.ip_address}:{node.port}/api/chain', timeout=1).json()

            # checking the chain
            balances = {}
            block_hash = ''
            for i, block in enumerate(chain):
                # checking the height
                if (i+1) != block['height']:
                    continue
                
                # checking the previous_hash
                if block['height'] > 1 and block['previous_hash'] != block_hash:
                    continue
                block_hash = block['block_hash']

                transactions = []
                tx = requests.get(f"http://{node.ip_address}:{node.port}/api/tx_block/{block['block_hash']}", timeout=1).json()
                for t in tx:
                    transactions.append(t)

                # checking the block and its transactions
                if not utils.check_block(block['block_hash'], block['height'], block['nonce'], block['timestamp'], block['previous_hash'], block['merkle_root'], transactions):
                    continue
                
                balances = utils.check_balances(transactions, balances)
            
            # checking the balance
            for address in balances:
                if float(balances[address]) < 0:
                    continue

            if len(chain) == 0:
                continue

            data = {
                'chain': chain,
                'ip_address': node.ip_address,
                'port': node.port,
                'length': len(chain),
            }
            chains.append(data)
        except:
            continue # ignore the node
            
    if len(chains) == 0:
        return redirect(request.META['HTTP_REFERER'])

    try:
        last_block = Block_header.objects.all().order_by('-height')[0]
    except:
        # add the longest chain
        chain = sorted(chains, key=lambda k: k['length'], reverse=True)[0]
        ip_address = chain['ip_address']
        port = chain['port']
        
        for block in chain['chain']:
            transactions = []
            tx = requests.get(f"http://{ip_address}:{port}/api/tx_block/{block['block_hash']}", timeout=1).json()
            for t in tx:
                transactions.append(t)
            Block_header.objects.add_block(block['block_hash'], block['height'], block['nonce'], block['timestamp'], block['previous_hash'], block['merkle_root'], transactions)
        return redirect(request.META['HTTP_REFERER'])
    
    for chain in sorted(chains, key=lambda k: k['length'], reverse=True):
        if int(chain['chain'][-1]['height']) > last_block.height:
            max_height = int(chain['chain'][-1]['height'])
            ip_address = chain['ip_address']
            port = chain['port']
            
            for block in chain['chain']:
                
                if block['previous_hash'] == 'eab06ee07b5534d39b0323bb5e2fee864b5617765ab82878482c1dbf1d035b88':
                    # each block is different, even the genesis block
                    if block['block_hash'] != Block_header.objects.all()[0].block_hash:
                        if (max_height + 1 - last_block.height) >= 6:
                            # replace chain
                            with transaction.atomic():
                                try:
                                    for block in Block_header.objects.all():
                                        Block_header.objects.invalidate_block(block)

                                    for block in chain['chain']:
                                        transactions = []
                                        tx = requests.get(f"http://{ip_address}:{port}/api/tx_block/{block['block_hash']}", timeout=1).json()
                                        for t in tx:
                                            transactions.append(t)
                                        Block_header.objects.add_block(block['block_hash'], block['height'], block['nonce'], block['timestamp'], block['previous_hash'], block['merkle_root'], transactions)
                                except:
                                    raise IntegrityError
                            return redirect(request.META['HTTP_REFERER'])
                        else:
                            return redirect(request.META['HTTP_REFERER'])

                elif block['block_hash'] == str(last_block.block_hash):
                    # add new blocks
                    for block in chain['chain']:
                        if block['height'] > last_block.height:
                            with transaction.atomic():
                                try:
                                    transactions = []
                                    tx = requests.get(f"http://{ip_address}:{port}/api/tx_block/{block['block_hash']}", timeout=1).json()
                                    for t in tx:
                                        transactions.append(t)
                                    Block_header.objects.add_block(block['block_hash'], block['height'], block['nonce'], block['timestamp'], block['previous_hash'], block['merkle_root'], transactions)
                                except:
                                    raise IntegrityError
                    return redirect(request.META['HTTP_REFERER'])

                elif int(block['height']) == last_block.height:
                    if (max_height + 1 - last_block.height) >= 6:
                        # replace chain
                        with transaction.atomic():
                            try:
                                for block in Block_header.objects.all():
                                    Block_header.objects.invalidate_block(block)

                                for block in chain['chain']:
                                    transactions = []
                                    tx = requests.get(f"http://{ip_address}:{port}/api/tx_block/{block['block_hash']}", timeout=1).json()
                                    for t in tx:
                                        transactions.append(t)
                                    Block_header.objects.add_block(block['block_hash'], block['height'], block['nonce'], block['timestamp'], block['previous_hash'], block['merkle_root'], transactions)
                            except:
                                raise IntegrityError
                        return redirect(request.META['HTTP_REFERER'])
                    else:
                        return redirect(request.META['HTTP_REFERER'])

    return redirect(request.META['HTTP_REFERER'])

@login_required
@require_GET
def mine(request):
    if len(Block_header.objects.all()) == 0:
        Block_header.objects.create_genesis_block(request.user.address.address)
        return redirect(request.META['HTTP_REFERER'])

    # getting the height and previous_hash
    block = Block_header.objects.all().order_by('-height')[0]
    height = int(block.height) + 1
    previous_hash = block.block_hash

    # getting the coinbase_tx
    coinbase_tx = Transaction.objects.create_coinbase_tx(request.user.address.address)
    transactions = []
    tx_to_send = []
    transactions.append(coinbase_tx)
    tx_to_send.append({
        'tx_hash': coinbase_tx.tx_hash,
        'sender': coinbase_tx.sender,
        'receiver': coinbase_tx.receiver,
        'amount': str('%.4f' % coinbase_tx.amount),
        'fee': str('%.4f' % coinbase_tx.fee),
        'sender_public_key': coinbase_tx.sender_public_key,
        'timestamp': coinbase_tx.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
        'signature': coinbase_tx.signature,
    })

    # collecting mempool transactions
    Mempool.objects.check_mempool()
    contador = 0
    total_fee = float(0.0)
    for tx in Mempool.objects.all().order_by('-fee', '-timestamp'):
        if contador < 6:
            t = Transaction.objects.get(tx_hash=tx.tx_hash)
            transactions.append(t)
            tx_to_send.append({
                'tx_hash': t.tx_hash,
                'sender': t.sender,
                'receiver': t.receiver,
                'amount': str('%.4f' % t.amount),
                'fee': str('%.4f' % t.fee),
                'sender_public_key': t.sender_public_key,
                'timestamp': t.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
                'signature': t.signature,
            })
            contador += 1
            total_fee += float(t.fee)
        else:
            break

    # getting the fee_tx
    if total_fee > 0.0:
        fee_tx = Transaction.objects.create_fee_tx(request.user.address.address, float('%.4f' % total_fee))
        transactions.append(fee_tx)
        tx_to_send.append({
            'tx_hash': fee_tx.tx_hash,
            'sender': fee_tx.sender,
            'receiver': fee_tx.receiver,
            'amount': str('%.4f' % fee_tx.amount),
            'fee': str('%.4f' % fee_tx.fee),
            'sender_public_key': fee_tx.sender_public_key,
            'timestamp': fee_tx.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            'signature': fee_tx.signature,
        })

    # calculating the merkle_root
    hashes = []
    for tx in transactions:
        hashes.append(tx.tx_hash)
    merkle_root = utils.get_merkle_root(hashes)

    # mining the block
    nonce = 0
    block_hash = '-'
    timestamp = datetime.now()
    str_timestamp = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")
    while block_hash[:5] != '00000':
        nonce += 1
        string = str(height) + str(nonce) + str_timestamp + previous_hash + merkle_root
        block_hash = hashlib.sha256(string.encode()).hexdigest()
    
    # saving it
    with transaction.atomic():
        index = 0
        try:
            block = Block_header(block_hash=block_hash, height=height, nonce=nonce, timestamp=timestamp, previous_hash=previous_hash, merkle_root=merkle_root)
            block.save()
            for tx in transactions:
                if tx.sender == '':
                    tx.save()
                if not Block_transaction.objects.create_instance(tx, index, block):
                    raise IntegrityError
                if tx.sender != '':
                    Mempool.objects.get(tx_hash=tx).delete()
                index += 1
            
            # sharing the block with the rest of nodes
            for node in Node.objects.all():
                try:
                    url = f'http://{node.ip_address}:{node.port}/api/store_block/'
                    data = {
                        'block_hash': block_hash,
                        'height': height,
                        'nonce': nonce,
                        'timestamp': timestamp,
                        'previous_hash': previous_hash,
                        'merkle_root': merkle_root,
                        'transactions': base64.b64encode(str(tx_to_send).encode()).decode(),
                    }
                    r = requests.post(url, data=data, timeout=1)
                    # we don't need to check the status code received
                except:
                    pass # ignore the node

            return redirect(request.META['HTTP_REFERER'])
        except:
            raise IntegrityError
    return redirect(request.META['HTTP_REFERER'])