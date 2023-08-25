"""
sudo apt install libmariadb3 libmariadb-dev
python3 -m pip install pycryptodome
pip3 install mariadb
"""

import hashlib
from Crypto.Hash import SHA256
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
import requests
from flask import Flask, jsonify, request
import binascii
import mariadb

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.orphans= []
        self.forks= []
        self.nodes = set()
        self.recipients=[]
        # inicializar con la base de datos
        self.chain = [[],[]]
        #print(self.chain[1])
        # Create the genesis block
        self.new_block(previous_hash='1', proof=100,transactions=self.current_transactions,timestamp=time())
    
    def initialize(self, id):
        self.chain[1]==self.init_senders(id)
        self.recipients=self.init_recipients(id)

    def init_recipients(self,id):
        try:
            conn = mariadb.connect(
                user="alumne",
                password="alumne",
                host="127.0.0.1",
                port=3306,
                database=id
            )

        except mariadb.Error as e:
            print(f"Error connecting to MariaDB Platform: {e}")
        cur = conn.cursor()
        
        cur.execute(
            "SELECT pk FROM sendersPK")
        
        tmp=[]
        for (pk) in cur: tmp.append(pk)
        return tmp

    def init_senders(self,id):
        try:
            conn = mariadb.connect(
                user="alumne",
                password="alumne",
                host="127.0.0.1",
                port=3306,
                database=id
            )

        except mariadb.Error as e:
            print(f"Error connecting to MariaDB Platform: {e}")
        cur = conn.cursor()
        
        cur.execute(
            "SELECT pk FROM sendersPK")
        
        tmp=[]
        for (pk) in cur: tmp.append(pk)
        return tmp

    def encode_signature(self, sig):
        chain=bytes()
        for i in range(0,367,46):
            chain+=binascii.a2b_uu(sig[i:i+46])
        return chain

    def modify_senders(self,key):
        self.chain[1].append(key)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def choose_chain(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain[0])
        chains=[self.chain[0]]
        times=[1]
        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if self.valid_chain(chain):
                    chains.append(chain)
                    if len(chain) > max_length:
                        max_length = length
                        new_chain = chain
        max_count=1

        for ch in chains:
            count=chains.count(ch)
            if count>len(chains)/2:
                return ch
            if count>max_count:
                max_count=count
                new_chain=ch
                max_length=len(ch)
            if count==max_count and len(ch)>max_length:
                max_length=len(ch)
                new_chain=ch

        return new_chain

    def valid_transaction(self, transaction):
        sender=RSA.import_key(transaction['sender'])
        if not (transaction['sender'] in self.chain[1] or not (transaction['recipient']) in self.recipients):
            return False
        message='signature'
        h=SHA256.new(message.encode())
        signature=self.encode_signature(transaction['signature'].encode())
        try:
            pkcs1_15.new(sender).verify(h, signature)
        except (ValueError, TypeError):
            return False
        return True

    def valid_block(self, block):
        if len(self.chain[0])==0: return True
        if not self.valid_proof(block['proof'], block['previous_hash'], block['timestamp']):
            return False
        if self.repeated_block(block):
            return False
        for trans in block['transactions']:
            if not self.valid_transaction(trans):
                return False
        return True

    def repeated_block(self, block):
        for b in self.chain[0]:
            if b==block: return True
        return False

    def repeated_transaction(self, sender):      
        for trans in self.current_transactions:
            if trans['sender']==sender:
                return True
        return False

# may be deleted
    """
    def exists_transaction(self,transaction):
        ref=transaction['ref']
        if transaction in self.current_transactions:
            return True
        for block in self.chain[0]:
            transactions=block['transactions']
            for trans in transactions:
                if hashlib.sha256(trans).hexdigest()==ref:
                    return True
        return False
    """

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            #if not self.valid_proof(last_block['proof'], block['proof'], last_block['previous_hash']):
            if not self.valid_proof(block['proof'], block['previous_hash'], block['timestamp']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain[0])

        for fork in self.forks:
            length = len(fork[0])
                # Check if the length is longer and the chain is valid
            if length > max_length:
                max_length = length
                new_chain = fork

        for fork in self.forks:
            if len(fork[0])<max_length-2:
                self.forks.remove(fork)
        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            if len(self.chain[0])>=max_length-2:
                self.forks.append(self.chain)
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash, transactions, timestamp):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        self.resolve_conflicts()
        block = {
            'index': len(self.chain) + 1,
            'timestamp': timestamp,
            'transactions': transactions,
            'proof': proof,
            'previous_hash': previous_hash,
        }

        if not self.valid_block(block):
            return {}
        # Reset the current list of transactions
        self.clean_transactions(transactions);
        search=self.search_in_chain(self.chain,block)
        if search==1:
            self.chain[1]=self.clean_senders(self.chain[1],block)
            self.chain[0].append(block)
            self.traverse_orphans(self.chain,self.hash(block))
        elif search==2:
            self.traverse_orphans(self.forks[-1],self.hash(block))
        else:
            parents=False
            for fork in self.forks:
                search=self.search_in_chain(fork,block)
                if search==1:
                    fork[1]=self.clean_senders(fork[1],block)
                    fork[0].append(block)
                    self.traverse_orphans(fork,self.hash(block))
                    parents=True
                    break
                elif search==2:
                    self.traverse_orphans(self.forks[-1],self.hash(block))
                    parents=True
                    break
            if not parents:
                self.orphans.append(block)
        return block

    def search_in_chain(self, ch, block):
        if len(self.chain[0])==0:
            return 1
        if block['previous_hash']==self.hash(ch[0][-1]):
            return 1
        if len(ch[0])>1:
            if block['previous_hash']==self.hash(ch[0][-2]):
                temp=ch[0:len(ch)-2]
                temp.append(block)
                temp2=self.clean_senders(ch[1],block)
                self.forks.append([temp,temp2])
                return 2
        return 3

    def traverse_orphans(self, ch, hash):
        for b in self.orphans:
            if b['previous_hash']==hash:
                self.orphans.remove(b)
                ch[0].append(b)
                ch[1]=self.clean_senders(ch[1],b)
                self.traverse_orphans(ch,self.hash(b))
                break

    def clean_transactions(self, transactions):
        self.current_transactions = [x for x in self.current_transactions if x not in transactions]

    def clean_senders(self,previous_senders, block):
        for trans in block['transactions']:
            previous_senders.remove(trans['sender'])
        return previous_senders

    def new_transaction(self, sender, recipient, signature):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :return: The index of the Block that will hold this transaction
        """
        transaction={
            'sender': sender,
            'recipient': recipient,
            'signature': signature,
        }
        if self.repeated_transaction(sender): return -1
        if self.valid_transaction(transaction):
            return -1
        self.current_transactions.append(transaction)
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[0][-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, previous_hash, timestamp):
        proof = 0
        while self.valid_proof(proof,previous_hash,timestamp) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(proof, previous_hash, timestamp):
        guess = f'{proof}{previous_hash}{timestamp}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    timestamp=time()
    previous_hash = blockchain.hash(last_block)
    proof = blockchain.proof_of_work(previous_hash,timestamp)

    block = blockchain.new_block(proof, previous_hash,blockchain.current_transactions,timestamp)
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/transactions/modify', methods=['POST'])
def send_key():
    values = request.get_json()
    required = ['path']
    if not all(k in values for k in required):
        return 'Missing values', 400
    key = RSA.import_key(open(values['path']).read())
    blockchain.modify_senders(key)
    response = {'message': f'Sender will be added to Senders list'}
    return jsonify(response), 201

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    # Create a new Transaction
    
    index = blockchain.new_transaction(values['sender'], values['recipient'], values['signature'])

    if index==-1:
        response={'Message': 'Error'}
        return jsonify(response), 400

 
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    #for node in nodes:
    #    blockchain.register_node(node)
    blockchain.register_node(nodes)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    chain= blockchain.choose_chain()

    response = {
        'chain': chain
    }

    return jsonify(response), 200

@app.route('/nodes/list', methods=['GET'])
def getNodes():
    response={'nodes':str(blockchain.nodes)}
    return jsonify(response), 200

@app.route('/validate', methods=['GET'])
def validate():
    if blockchain.valid_chain(blockchain.chain):
        return "The stored chain is valid\n", 200
    else:
        return "The stored chain is not valid\n", 200

if __name__ == '__main__':
    from argparse import ArgumentParser
    print("Ejecucion main")
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-i', '--identifier',default="none",type=str,help='Data base identifier')
    args = parser.parse_args()
    port = args.port
    id=args.identifier
    if id=="none":
        print("Identifier mandatory. Usage: python3 blockchain.py -i database_identifier")
        exit(1)
    blockchain.initialize(id)
    app.run(host='0.0.0.0', port=port)
