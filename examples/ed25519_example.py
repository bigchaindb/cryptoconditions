################################################################################################################
# Code upgrade done by Via Science Inc.                                                                        #
#                                                                                                              #
# This is to confirm that my company has agreed to and accepted the Planetmint Entity Contributor Agreement    #
# at https://www.planetmint.com/cla/ and to represent and warrant that I have authority to do so.              #
#                                                                                                              #
# USq6mSPklezAirGcWi6ntfAlG2OhEobGhnNIstM6xH4UCZGX5KgXQemE4wLk0R6                                              #
################################################################################################################

import binascii
import base58

import cryptoconditions as cc
from cryptoconditions.crypto import Ed25519SigningKey as SigningKey

message = "Hello World! Conditions are here!"
sk_b58 = base58.b58encode(binascii.unhexlify("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"))
sk = SigningKey(sk_b58)

ed25519_fulfillment = cc.Ed25519Sha256()
ed25519_fulfillment.sign(message.encode(), base58.b58decode(sk.encode()))

print(ed25519_fulfillment.condition_uri)
# prints 'ni:///sha-256;U1YhFdW0lOI-SVF3PbDP4t_lVefj_-tB5P11yvfBaoE?fpt=ed25519-sha-256&cost=131072'
print(ed25519_fulfillment.serialize_uri())
# prints 'pGSAIOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_gUC2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6D' \
#        'HISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK'

fulfillment_uri = (
    "pGSAIOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_gUC2IpH62UMvjymLnEpIldvik_b_"
    "2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK"
)
condition_uri = "ni:///sha-256;U1YhFdW0lOI-SVF3PbDP4t_lVefj_-tB5P11yvfBaoE?fpt=ed25519-sha-256&cost=131072"

fulfillment = cc.Fulfillment.from_uri(fulfillment_uri)

result = fulfillment.validate(message=message.encode()) and condition_uri == fulfillment.condition_uri
print(result)


sk_b58 = base58.b58encode(binascii.unhexlify("1a3ab1a87f000348f391613930cc49529652ecf2d2c7cadfd96e87a7f6de948a"))
sk = SigningKey(sk_b58)
vk = sk.get_verifying_key()

ed25519_fulfillment = cc.Ed25519Sha256(public_key=base58.b58decode(vk.encode()))
ed25519_fulfillment.sign(message.encode(), base58.b58decode(sk.encode()))

print(ed25519_fulfillment.condition_uri)
# prints 'ni:///sha-256;N6TKMeDfpJXJ9phg2scQcVoGNlr-HfbzCrwzuJ5fFHE?fpt=ed25519-sha-256&cost=131072'
print(ed25519_fulfillment.serialize_uri())
# prints 'pGSAIKYU1joovj6OReqZY40iq8BDDkESoos_YBphf5x_RFAhgUAXkJ3NhSGXDidLJME_Pcg9Qp7rFaQmk9JSP7DfOEWl7Ml06AgVUD' \
# 'fMTmd8DiRMxDYY2CDq45hUlTXYvJoOCaEF'
