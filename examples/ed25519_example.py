import binascii
import base58

import cryptoconditions as cc
from cryptoconditions.crypto import Ed25519SigningKey as SigningKey

message = 'Hello World! Conditions are here!'
sk_b58 = base58.b58encode(binascii.unhexlify('833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42'))
sk = SigningKey(sk_b58)

ed25519_fulfillment = cc.Ed25519Fulfillment()
ed25519_fulfillment.sign(message, sk)

print(ed25519_fulfillment.condition_uri)
# prints 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'
print(ed25519_fulfillment.serialize_uri())
# prints 'cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8ui
#        'sHOyGpR1FISer26CdG28zHAcK'

fulfillment_uri = 'cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal' \
                  '6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK'
condition_uri = 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'

fulfillment = cc.Fulfillment.from_uri(fulfillment_uri)

result = fulfillment.validate(message) and condition_uri == fulfillment.condition_uri
print(result)


sk_b58 = base58.b58encode(binascii.unhexlify('1a3ab1a87f000348f391613930cc49529652ecf2d2c7cadfd96e87a7f6de948a'))
sk = SigningKey(sk_b58)
vk = sk.get_verifying_key()

ed25519_fulfillment = cc.Ed25519Fulfillment(public_key=vk)
ed25519_fulfillment.sign(message, sk)

print(ed25519_fulfillment.condition_uri)
# prints 'cc:4:20:phTWOii-Po5F6pljjSKrwEMOQRKiiz9gGmF_nH9EUCE:96'
print(ed25519_fulfillment.serialize_uri())
# prints 'cf:4:phTWOii-Po5F6pljjSKrwEMOQRKiiz9gGmF_nH9EUCEXkJ3NhSGXDidLJME_Pcg9Qp7rFaQmk9JSP7DfOEWl7Ml06AgVUDfMTmd8Di
#        'RMxDYY2CDq45hUlTXYvJoOCaEF'

