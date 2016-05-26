[![Build Status](https://travis-ci.org/bigchaindb/cryptoconditions.svg?branch=master)](https://travis-ci.org/bigchaindb/cryptoconditions)
[![PyPI](https://img.shields.io/pypi/v/cryptoconditions.svg)](https://pypi.python.org/pypi/cryptoconditions)
[![codecov.io](https://codecov.io/github/bigchaindb/cryptoconditions/coverage.svg?branch=master)](https://codecov.io/github/bigchaindb/cryptoconditions?branch=master)


# How to install and run tests

First clone this repository (optional: and a virtual env).
Note that we support **Python>=3.4**.

Install from pypi:

```
$ pip install cryptocondtions
```

Or install from source
```
$ pip install -e .[dev]
$ py.test -v
```


# Crypto Conditions

This spec is a python port from the [**Interledger Protocol (ILP)**]
(https://interledger.org/five-bells-condition/spec.html)

## Motivation

We would like a way to describe a signed message such that multiple actors in a
distributed system can all verify the same signed message and agree on whether
it matches the description.

This provides a useful primitive for distributed, event-based systems since we
can describe events (represented by signed messages) and therefore define
generic authenticated event handlers.

## Usage

```python
import binascii
import cryptoconditions as cc

# Parse a condition from a URI
example_condition_uri = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
parsed_condition = cc.Condition.from_uri(example_condition_uri)
print(isinstance(parsed_condition, cc.Condition))
# prints True

print(binascii.hexlify(parsed_condition.hash))
# prints b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

# Compile a condition
parsed_condition_uri = parsed_condition.serialize_uri()
print(parsed_condition_uri)
# prints 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
print(parsed_condition_uri == example_condition_uri)
# prints True

# Parse a fulfillment
example_fulfillment_uri = 'cf:0:'
parsed_fulfillment = cc.Fulfillment.from_uri(example_fulfillment_uri)
print(isinstance(parsed_fulfillment, cc.PreimageSha256Fulfillment))
# prints True

# Retrieve the condition of the fulfillment 
print(parsed_fulfillment.condition_uri)
# prints 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'

# Validate a fulfillment
parsed_fulfillment.validate()
# prints True

# Export to JSON
json_data = parsed_fulfillment.serialize_json()
print(json_data)
# prints '{"bitmask": 3, "type_id": 0, "type": "fulfillment", "preimage": ""}'

# Parse fulfillment from JSON
import json
json_fulfillment = cc.Fulfillment.from_json(json.loads(json_data))
print(json_fulfillment.serialize_uri())
# prints 'cf:0:'
```

## ILP Format

### Condition

Conditions are ASCII encoded as:

```
"cc:" BASE16(TYPE) ":" BASE16(FEATURE_BITMASK) ":" BASE64URL(FINGERPRINT) ":" BASE10(MAX_FULFILLMENT_LENGTH)
```

Conditions are binary encoded as:

```
CONDITION =
  INT TYPE
  OCTET_STRING TYPE_BITMASK
  OCTET_STRING FINGERPRINT
  INT MAX_FULFILLMENT_LENGTH
```

### Fulfillment

Fulfillments are ASCII encoded as:

```
"cf:" BASE16(TYPE) ":" BASE64URL(PAYLOAD)
```

Fulfillments are binary encoded as:

```
FULFILLMENT =
  INT TYPE
  OCTET_STRING PAYLOAD
```

# Condition Types

## Preimage-SHA-256

### Condition

```
HASH = SHA256(PREIMAGE)
```

### Fulfillment

```
FULFILLMENT_PAYLOAD =
  VARBYTES PREIMAGE
```

### Usage

```python
import binascii, hashlib
import cryptoconditions as cc

secret = ''
puzzle = binascii.hexlify(hashlib.sha256(secret.encode()).digest())
print(puzzle)
# prints b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

# Create a SHA256 condition
sha256condition = cc.Condition()
sha256condition.type_id = cc.PreimageSha256Fulfillment.TYPE_ID
sha256condition.bitmask = cc.PreimageSha256Fulfillment.FEATURE_BITMASK
sha256condition.hash = binascii.unhexlify(puzzle)
sha256condition.max_fulfillment_length = 0
sha256condition_uri = sha256condition.serialize_uri()
print(sha256condition_uri)
# prints 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'

# Create a fulfillment
sha256fulfillment = cc.PreimageSha256Fulfillment()

# Create a condition from fulfillment
sha256fulfillment.condition
# raises ValueError: Could not calculate hash, no preimage provided
sha256fulfillment.preimage = secret
print(sha256fulfillment.condition.serialize_uri() == sha256condition_uri)
# prints True

# Compile a fulfillment
print(sha256fulfillment.serialize_uri())
# prints 'cf:0:'

# Even better: verify that the fulfillment matches the condition
print(sha256fulfillment.validate() and \
    sha256fulfillment.condition.serialize_uri() == sha256condition.serialize_uri())
# prints True
```

## RSA-SHA-256

**Warning:** not (yet) implemented in `cryptoconditions`, for info see the
[**ILP specification**](https://interledger.org/five-bells-condition/spec.html)

## ED25519

### Condition

```
HASH = UINT256 PUBLIC_KEY
```

### Fulfillment

```
FULFILLMENT_PAYLOAD =
  UINT256 PUBLIC_KEY
  UINT512 SIGNATURE
```

### Usage

```python
import cryptoconditions as cc

# We use base58 key encoding
sk = cc.crypto.Ed25519SigningKey(b'9qLvREC54mhKYivr88VpckyVWdAFmifJpGjbvV5AiTRs')
vk = sk.get_verifying_key()

# Create an ED25519-SHA256 condition
ed25519_fulfillment = cc.Ed25519Fulfillment(public_key=vk)
ed25519_condition_uri = ed25519_fulfillment.condition.serialize_uri()
print (ed25519_condition_uri)
# prints 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'

# ED25519-SHA256 condition not fulfilled
print(ed25519_fulfillment.validate())
# prints False

# Fulfill an ED25519-SHA256 condition
message = 'Hello World! Conditions are here!'
ed25519_fulfillment.sign(message, sk)
print(ed25519_fulfillment.validate(message))
# prints True

print(ed25519_fulfillment.serialize_uri())
# prints 'cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK'
print(ed25519_fulfillment.condition_uri)
# prints 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'

# Parse a fulfillment URI
parsed_ed25519_fulfillment = cc.Ed25519Fulfillment.from_uri('cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK')

print(parsed_ed25519_fulfillment.validate(message))
# prints True
print(parsed_ed25519_fulfillment.condition.serialize_uri())
# prints 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'
```

## THRESHOLD-SHA-256

### Condition

```
HASH = SHA256(
  VARUINT TYPE_BIT
  VARUINT THRESHOLD
  VARARRAY
    VARUINT WEIGHT
    VARBYTES PREFIX
    CONDITION
)
```


### Fulfillment

```
FULFILLMENT_PAYLOAD =
  VARUINT THRESHOLD
  VARARRAY
    UINT8 FLAGS
    OPTIONAL VARUINT WEIGHT   ; if  FLAGS & 0x40
    OPTIONAL VARBYTES PREFIX  ; if  FLAGS & 0x20
    OPTIONAL FULFILLMENT      ; if  FLAGS & 0x80
    OPTIONAL CONDITION        ; if ~FLAGS & 0x80
```

### Usage

```python
import cryptoconditions as cc

# Parse some fulfillments
ed25519_fulfillment = cc.Ed25519Fulfillment.from_uri('cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK')

# Create a 1-of-2 threshold condition (OR gate)
threshold_fulfillment = cc.ThresholdSha256Fulfillment(threshold=1)
# Add as an object or by URI
threshold_fulfillment.add_subfulfillment_uri('cf:0:')
threshold_fulfillment.add_subfulfillment(ed25519_fulfillment)
print(threshold_fulfillment.condition_uri)
# prints 'cc:2:2b:mJUaGKCuF5n-3tfXM2U81VYtHbX-N8MP6kz8R-ASwNQ:146'

# Compile a threshold fulfillment
threshold_fulfillment_uri = threshold_fulfillment.serialize_uri()
# Note: If there are more than enough fulfilled subconditions, shorter
# fulfillments will be chosen over longer ones.
print(threshold_fulfillment_uri)
# prints 'cf:2:AQEBAgEBAwAAAAABAQAnAAQBICDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfivwFg'

# Validate fulfillment
message = 'Hello World! Conditions are here!'
print(threshold_fulfillment.validate(message))
# prints True

# Parse the fulfillment
reparsed_fulfillment = cc.ThresholdSha256Fulfillment.from_uri(threshold_fulfillment_uri)
print(reparsed_fulfillment.validate(message))
# prints True

# Increase threshold to a 3-port AND gate
threshold_fulfillment.threshold = 3
print(threshold_fulfillment.validate(message))
# prints False

# Create a nested threshold condition
# VALID = SHA and DSA and (DSA or DSA)
nested_fulfillment = cc.ThresholdSha256Fulfillment(threshold=1)
nested_fulfillment.add_subfulfillment(ed25519_fulfillment)
nested_fulfillment.add_subfulfillment(ed25519_fulfillment)
threshold_fulfillment.add_subfulfillment(nested_fulfillment)
threshold_fulfillment.threshold = 3 # AND gate

print(threshold_fulfillment.serialize_uri())
# prints 'cf:2:AQMBAwEBAwAAAAABAWMABGDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfiv7YikfrZQy-PKYucSkiV2-KT9v_aGmja3wzN719HoMchKl_qPNqXo_TAPqny6Kwc7IalHUUhJ6vboJ0bbzMcBwoAAQGBmgACgZYBAQECAQEAJwAEASAg7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8BYAEBYwAEYOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_tiKR-tlDL48pi5xKSJXb4pP2_9oaaNrfDM3vX0egxyEqX-o82pej9MA-qfLorBzshqUdRSEnq9ugnRtvMxwHCgAA'
threshold_fulfillment.serialize_json()
```

```python
  {
   "bitmask":43,
   "subfulfillments":[
     {
       "bitmask":3,
       "preimage":"",
       "type":"fulfillment",
       "type_id":0,
       "weight":1
     },
     {
       "bitmask":32,
       "public_key":"Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU",
       "signature":"4eCt6SFPCzLQSAoQGW7CTu3MHdLj6FezSpjktE7tHsYGJ4pNSUnpHtV9XgdHF2XYd62M9fTJ4WYdhTVck27qNoHj",
       "type":"fulfillment",
       "type_id":4,
       "weight":1
     },
     {
       "bitmask":41,
       "subfulfillments":[
         {
           "bitmask":32,
           "public_key":"Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU",
           "signature":"4eCt6SFPCzLQSAoQGW7CTu3MHdLj6FezSpjktE7tHsYGJ4pNSUnpHtV9XgdHF2XYd62M9fTJ4WYdhTVck27qNoHj",
           "type":"fulfillment",
           "type_id":4,
           "weight":1
         },
         {
           "bitmask":32,
           "public_key":"Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU",
           "signature":"4eCt6SFPCzLQSAoQGW7CTu3MHdLj6FezSpjktE7tHsYGJ4pNSUnpHtV9XgdHF2XYd62M9fTJ4WYdhTVck27qNoHj",
           "type":"fulfillment",
           "type_id":4,
           "weight":1
         }
       ],
       "threshold":1,
       "type":"fulfillment",
       "type_id":2,
       "weight":1
     }
   ],
   "threshold":3,
   "type":"fulfillment",
   "type_id":2
 }
```


## (unofficial) Timeout-SHA-256

Extends Preimage-SHA-256

### Condition

```
HASH = SHA256(EXPIRE_TIME)
```


### Fulfillment

```
FULFILLMENT_PAYLOAD =
  VARBYTES EXPIRE_TIME
```

### Usage

```python
from time import sleep

import cryptoconditions as cc
from cryptoconditions.types.timeout import timestamp

time_expire = str(float(timestamp()) + 5)  # 5 secs from now
timeout_fulfillment = cc.TimeoutFulfillment(expire_time=time_expire)

# Small test to see the state change
for i in range(8):
    timeout_valid = timeout_fulfillment.validate(now=timestamp())
    seconds_to_timeout = int(float(time_expire) - float(timestamp()))
    print('timeout_fulfillment valid: {} ({}s to timeout)'.format(timeout_valid, seconds_to_timeout))
    sleep(1)
```

```python
timeout_fulfillment valid: True (3s to timeout)
timeout_fulfillment valid: True (2s to timeout)
timeout_fulfillment valid: True (1s to timeout)
timeout_fulfillment valid: True (0s to timeout)
timeout_fulfillment valid: False (0s to timeout)
timeout_fulfillment valid: False (-1s to timeout)
timeout_fulfillment valid: False (-2s to timeout)
timeout_fulfillment valid: False (-3s to timeout)
```