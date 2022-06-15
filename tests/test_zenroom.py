# GOAL:
# In this script I tried to implement the ECDSA signature using zenroom

# However, the scripts are customizable and so with the same procedure
# we can implement more complex smart contracts

# PUBLIC IDENTITY
# The public identity of the users in this script (Bob and Alice)
# is the pair (ECDH public key, Testnet address)

import json

import hashlib
from cryptoconditions import ZenroomSha256, Fulfillment
from zenroom import zencode_exec
from json.decoder import JSONDecodeError

# from zenroom import zencode_exec

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
    return json.loads(zencode_exec(GENERATE_KEYPAIR).output)['keyring']

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
    Given I have the 'keyring'
    When I create the ecdh public key
    When I create the testnet address
    Then print my 'ecdh public key'
    Then print my 'testnet address'"""

def sk2pk(name, keys):
    return json.loads(zencode_exec(SK_TO_PK.format(name),
                                   keys=json.dumps({'keyring': keys})).output)
# Alice assert the composition of the houses

# zen_public_keys is an identity dictionary

def test_zenroom():
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

    # the result key is the expected result of the fulfill script
    # it depends on the script, in this case I know that
    #     `Then print the string 'ok'`,
    # results in
    #     { "output": ["ok"] }
    metadata = {
            "result": {
                "output": ["ok"]
            }
    }

    version = '2.0'

    fulfill_script = """Rule input encoding base58
    Rule output encoding base58
    Scenario 'ecdh': Bob verifies the signature from Alice
    Given I have a 'ecdh public key' from 'Alice'
    Given that I have a 'string dictionary' named 'houses' inside 'asset'
    Given I have a 'signature' named 'signature' inside 'result'
    When I verify the 'houses' has a signature in 'signature' by 'Alice'
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
        'metadata': metadata,
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
        Given I have the 'keyring'
        Given that I have a 'string dictionary' named 'houses' inside 'asset'
        When I create the signature of 'houses'
        Then print the 'signature'
        """

    # THIS FILLS THE METADATA WITH THE RESULT
    try:
        assert(not zenSha.validate(message=message))
    except:
        pass

    message = zenSha.sign(message, condition_script, alice)
    assert(zenSha.validate(message=message))

    # CRYPTO-CONDITIONS: generate the fulfillment uri
    fulfillment_uri = zenSha.serialize_uri()

    ff_from_uri = ZenroomSha256.from_uri(fulfillment_uri)
    ff_from_uri_ = Fulfillment.from_uri(fulfillment_uri)
    
    assert ff_from_uri.script == zenSha.script
    assert ff_from_uri.data == zenSha.data
    assert ff_from_uri.keys == zenSha.keys

    assert ff_from_uri_.script == zenSha.script
    assert ff_from_uri_.data == zenSha.data
    assert ff_from_uri_.keys == zenSha.keys
