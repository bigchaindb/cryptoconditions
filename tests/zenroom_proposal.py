# GOAL:
# In this script I tried to implement the ECDSA signature using zenroom

# However, the scripts are customizable and so with the same procedure
# we can implement more complex smart contracts

# PUBLIC IDENTITY
# The public identity of the users in this script (Bob and Alice)
# is the pair (ECDH public key, Testnet address)

import json

import hashlib
from cryptoconditions import ZenroomSha256

from zenroom import zencode_exec
import rapidjson

# from bigchaindb_driver import BigchainDB
# # bdb_root_url = 'https://ipdb3.riddleandcode.com'
# bdb_root_url = 'http://localhost:9984/'
# bdb = BigchainDB(bdb_root_url)


# The procedure to generate the keyring cannot be
# fixed in the code base, it depends on the particular
# smart contract
GENERATE_KEYPAIR = \
    """Rule input encoding base58
    Rule output encoding base58
    Scenario 'ecdh': Create the keypair
    Given that I am known as 'Pippo'
    When I create the ecdh key
    When I create the testnet key
    Then print data"""

def genkey():
    return rapidjson.loads(zencode_exec(GENERATE_KEYPAIR).output)['keys']

# There is not a unique way of generating the public
# key, for example, for the testnet I don't want the
# public key but the address (but there could exist
# a script in which the user want the public key and
# not the address)
# Thus we cannot fix it inside the script

# secret key to public key
SK_TO_PK = \
    """Rule input encoding base58
    Rule output encoding base58
    Scenario 'ecdh': Create the keypair
    Given that I am known as '{}'
    Given I have the 'keys'
    When I create the ecdh public key
    When I create the testnet address
    Then print my 'ecdh public key'
    Then print my 'testnet address'"""

def sk2pk(name, keys):
    return rapidjson.loads(zencode_exec(SK_TO_PK.format(name),
                                        keys=json.dumps({'keys': keys})).output)
# Alice assert the composition of the houses

# zen_public_keys is an identity dictionary

alice, bob = genkey(), genkey()
print("============== ALICE KEYPAIR =================")
print(alice)
print("============== BOB KEYPAIR =================")
print(bob)

asset = {
    "data": {
        "houses": [
            {
                "name": "Harry",
                "team": "Gryffindor",
            },
            {
                "name": "Draco",
                "team": "Slytherin",
            }
        ],
    }
}
zen_public_keys = sk2pk('Alice', alice)
zen_public_keys.update(sk2pk('Bob', bob))

data = {
    'also': 'more data'
}
print("============== PUBLIC IDENTITIES =================")
print(zen_public_keys)

metadata = {
}

version = '2.0'

fulfill_script = """Rule input encoding base58
Rule output encoding base58
Scenario 'ecdh': Bob verifies the signature from Alice
Given I have a 'ecdh public key' from 'Alice'
Given that I have a 'string dictionary' named 'houses' inside 'asset'
Given I have a 'signature' named 'data.signature' inside 'result'
When I verify the 'houses' has a signature in 'data.signature' by 'Alice'
Then print the string 'ok'
"""
# CRYPTO-CONDITIONS: instantiate an Ed25519 crypto-condition for buyer
zenSha = ZenroomSha256(script=fulfill_script, keys=zen_public_keys, data=data)

# CRYPTO-CONDITIONS: generate the condition uri
condition_uri = zenSha.condition.serialize_uri()
# CRYPTO-CONDITIONS: construct an unsigned fulfillment dictionary
unsigned_fulfillment_dict = {
    'type': zenSha.TYPE_NAME,
    'script': fulfill_script,
    'keys': zen_public_keys,
}

output = {
    'amount': '1000',
    'condition': {
        'details': unsigned_fulfillment_dict,
        'uri': condition_uri,
    },
    'data': data,
    'script': fulfill_script,
    'conf': '',
    'public_keys': (zen_public_keys['Alice']['ecdh_public_key'], ),
}


input_ = {
    'fulfillment': None,
    'fulfills': None,
    'owners_before': (zen_public_keys['Alice']['ecdh_public_key'], ),
}

token_creation_tx = {
    'operation': 'CREATE',
    'asset': asset,
    'metadata': None,
    'outputs': (output,),
    'inputs': (input_,),
    'version': version,
    'id': None,
}

# JSON: serialize the transaction-without-id to a json formatted string
message = json.dumps(
    token_creation_tx,
    sort_keys=True,
    separators=(',', ':'),
    ensure_ascii=False,
)

print("====== GENERATE RESULT (METADATA) =======")
condition_script = """Rule input encoding base58
    Rule output encoding base58
    Scenario 'ecdh': create the signature of an object
    Given I have the 'keys'
    Given that I have a 'string dictionary' named 'houses' inside 'asset'
    When I create the signature of 'houses'
    When I rename the 'signature' to 'data.signature'
    Then print the 'data.signature'
    """

# THIS FILLS THE METADATA WITH THE RESULT
assert(not zenSha.validate(message=message))
message = zenSha.sign(message, condition_script, alice)
assert(zenSha.validate(message=message))
# now metadata looks like
# 'metadata': {'result': {'data.signature': {'r': 'fdoan0GYo9RGP8y0fq+PKZ9Q1V8+VqJtBkSMB1tUnGQ=', 's': 'RnJCEepYJcVgFG/Y6cRc/2DWPaz5Pe5NpdRWegrZk5A='}}}

# CRYPTO-CONDITIONS: generate the fulfillment uri
fulfillment_uri = zenSha.serialize_uri()

# add the fulfillment uri (signature)
token_creation_tx['inputs'][0]['fulfillment'] = fulfillment_uri
print(token_creation_tx)

# JSON: serialize the id-less transaction to a json formatted string
json_str_tx = json.dumps(
    token_creation_tx,
    sort_keys=True,
    separators=(',', ':'),
    ensure_ascii=False,
)


# SHA3: hash the serialized id-less transaction to generate the id
shared_creation_txid = hashlib.sha3_256(json_str_tx.encode()).hexdigest()

# add the id
token_creation_tx['id'] = shared_creation_txid

#exit()
# send CREATE tx into the bdb network
#returned_creation_tx = bdb.transactions.send_async(token_creation_tx)

#print(returned_creation_tx)
