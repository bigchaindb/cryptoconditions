# GOAL:
# In this script I tried to implement the ECDSA signature using zenroom

# However, the scripts are customizable and so with the same procedure
# we can implement more complex smart contracts

# PUBLIC IDENTITY
# The public identity of the users in this script (Bob and Alice)
# is the pair (ECDH public key, Testnet address)

import json

from planetmint_cryptoconditions import ZenroomSha256, Fulfillment
from zenroom import zencode_exec
from json.decoder import JSONDecodeError
import pytest

# from zenroom import zencode_exec

# from bigchaindb_driver import BigchainDB
# # bdb_root_url = 'https://ipdb3.riddleandcode.com'
# bdb_root_url = 'http://localhost:9984/'
# bdb = BigchainDB(bdb_root_url)

# The procedure to generate the keyring cannot be
# fixed in the code base, it depends on the particular
# smart contract
GENERATE_KEYPAIR = """Rule input encoding base58
    Rule output encoding base58
    Scenario 'ecdh': Create the keypair
    Given that I am known as 'Pippo'
    When I create the ecdh key
    When I create the testnet key
    Then print keyring"""


def genkey():
    return json.loads(zencode_exec(GENERATE_KEYPAIR).output)


# There is not a unique way of generating the public
# key, for example, for the testnet I don't want the
# public key but the address (but there could exist
# a script in which the user want the public key and
# not the address)
# Thus we cannot fix it inside the script

# secret key to public key
SK_TO_PK = """Scenario 'ecdh': Create the keypair
    Given that I am known as '{}'
    Given I have the 'keyring'
    When I create the ecdh public key
    When I create the testnet address
    Then print my 'ecdh public key'
    Then print my 'testnet address'"""


def sk2pk(name, keys):
    return json.loads(zencode_exec(SK_TO_PK.format(name), keys=json.dumps(keys)).output)


# Alice assert the composition of the houses

# zen_public_keys is an identity dictionary


fulfillscript = """
    Scenario 'ecdh': Bob verifies the signature from Alice
    Given I have a 'ecdh public key' from 'Alice'
    Given that I have a 'string dictionary' named 'houses'
    Given I have a 'signature' named 'signature'
    When I verify the 'houses' has a signature in 'signature' by 'Alice'
    Then print the string 'ok'
    """

condictionalscript = """
        Scenario 'ecdh': create the signature of an object
        Given I have the 'keyring'
        Given that I have a 'string dictionary' named 'houses'
        When I create the signature of 'houses'
        Then print the 'signature'
        """


def test_valid_signature():
    alice, bob = genkey(), genkey()
    # the result key is the expected result of the fulfill script
    # it depends on the script, in this case I know that
    #     `Then print the string 'ok'`,

    script_input = {
        "input": {
            "houses": [
                {
                    "name": "Harry",
                    "team": "Gryffindor",
                },
                {
                    "name": "Draco",
                    "team": "Slytherin",
                },
            ],
        },
        "output": ["ok"],
    }

    zen_public_keys = sk2pk("Alice", alice)
    zen_public_keys.update(sk2pk("Bob", bob))
    data = {"also": "more data"}
    # CRYPTO-CONDITIONS: instantiate an Ed25519 crypto-condition for buyer
    zenSha = ZenroomSha256(script=fulfillscript, keys=zen_public_keys, data=data)

    # CRYPTO-CONDITIONS: generate the condition uri
    condition_uri = zenSha.condition.serialize_uri()
    script_input = json.dumps(script_input)

    # THIS FILLS THE METADATA WITH THE RESULT
    try:
        assert not zenSha.validate(message=script_input)
    except:
        pass

    message = zenSha.sign(script_input, condictionalscript, alice)
    # don't dump message like json.dumps(message) - beause this has already been performed by the sign-call
    output = json.loads(message)
    output["input"]["signature"] = output["output"]["signature"]  # verify input signature
    del output["output"]["signature"]
    del output["output"]["logs"]
    output["output"] = ["ok"]  # define expected output that is to be compared
    input_msg = json.dumps(output)
    assert zenSha.validate(message=input_msg)

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


def test_invalid_signing_call():
    alice, bob = genkey(), genkey()
    # the result key is the expected result of the fulfill script
    # it depends on the script, in this case I know that
    #     `Then print the string 'ok'`,

    script_input = {
        "input": {},
        "output": ["ok"],
    }

    zen_public_keys = sk2pk("Alice", alice)
    zen_public_keys.update(sk2pk("Bob", bob))

    data = {"also": "more data"}

    # CRYPTO-CONDITIONS: instantiate an Ed25519 crypto-condition for buyer
    zenSha = ZenroomSha256(script=fulfillscript, keys=zen_public_keys, data=data)

    # CRYPTO-CONDITIONS: generate the condition uri
    condition_uri = zenSha.condition.serialize_uri()
    script_input = json.dumps(script_input)

    # THIS FILLS THE METADATA WITH THE RESULT
    try:
        assert not zenSha.validate(message=script_input)
    except:
        pass

    message = zenSha.sign(script_input, condictionalscript, alice)
    # don't dump message like json.dumps(message) - beause this has already been performed by the sign-call
    assert not zenSha.validate(message=message)


def test_wrong_data():
    with pytest.raises(TypeError):
        ZenroomSha256(
            script="Given nothing",
            data={"asset": {}},
        )
    with pytest.raises(TypeError):
        ZenroomSha256(
            script="Given nothing",
            keys={"metadata": {}},
        )
    ZenroomSha256(
        script="Given nothing",
        keys={},
        data={},
    )


def test_empty_objects_in_asn1_dict():
    from planetmint_cryptoconditions.condition import Condition

    none_objs = ZenroomSha256(
        script="Given nothing",
        keys=None,
        data=None,
    )
    serialized_uri_ = none_objs.serialize_uri()
    asn1_dict = none_objs.condition.to_asn1_dict()
    ff = Fulfillment.from_uri(serialized_uri_)
    assert none_objs.script == ff.script
    assert none_objs.data == ff.data
    assert none_objs.keys == ff.keys


def test_no_asset_no_metadata():
    script = "Given nothing\nThen print the string 'Hello'"
    zenSha = ZenroomSha256(script=script)
    message = {"input": {}, "output": ["Hello"]}
    message = json.dumps(message)
    assert zenSha.validate(message=message)


def test_use_asset_and_metadata():
    script = """Given I have a 'string' named 'word1'
        Given I have a 'string' named 'word2'
        Given I have a 'string' named 'word3'
        When I append 'word2' to 'word1'
        When I append 'word3' to 'word1'
        Then print the 'word1'"""
    zenSha = ZenroomSha256(script=script)
    message = {"input": {"word3": "3", "word1": "1", "word2": "2"}, "output": {"word1": "123"}}
    message = json.dumps(message)
    assert zenSha.validate(message=message)


def test_valid_keys():
    zenSha = ZenroomSha256(
        script="Given I am 'Alice'\nGiven I have my 'keyring'\nThen print the string 'ok'",
        keys={
            "Alice": {
                "keyring": {
                    "bitcoin": "L1r9SjgSsaZUaiKb38mSYoZWGENg2J52kgCJyGAmPJNjrPzkcXWc",
                    "ecdh": "aODoXr8wCpFiVRc0RqWopKtS2wD73fqC1LyXJxePfnQ=",
                    "ethereum": "78ff5aaeabfa1b800ccab5c60dbaf1e249be5d2707993f4fbd27df09bca7e821",
                    "reflow": "BxsBo94hLKU96c0MX4GehsrQUfIGY7UgMqdZaWaHwrE=",
                    "schnorr": "aPC2VllaEbQJlQvo8KVKQGf8oMMGERb099sCbswpPq0=",
                }
            }
        },
    )

    message = {"output": ["ok"]}
    message = json.dumps(message)
    assert zenSha.validate(message=message)
    zenSha = ZenroomSha256(
        script="Given I have the 'keyring'\nThen print the string 'ok'",
        keys={
            "keyring": {
                "bitcoin": "L1r9SjgSsaZUaiKb38mSYoZWGENg2J52kgCJyGAmPJNjrPzkcXWc",
                "ecdh": "aODoXr8wCpFiVRc0RqWopKtS2wD73fqC1LyXJxePfnQ=",
                "ethereum": "78ff5aaeabfa1b800ccab5c60dbaf1e249be5d2707993f4fbd27df09bca7e821",
                "reflow": "BxsBo94hLKU96c0MX4GehsrQUfIGY7UgMqdZaWaHwrE=",
                "schnorr": "aPC2VllaEbQJlQvo8KVKQGf8oMMGERb099sCbswpPq0=",
            }
        },
    )

    message = {"output": ["ok"]}
    message = json.dumps(message)
    assert zenSha.validate(message=message)
