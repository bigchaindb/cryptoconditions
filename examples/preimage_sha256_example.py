import array

import binascii

import cryptoconditions as cc

my_fulfillment = cc.PreimageSha256Fulfillment('')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\x00')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:bjQLnP-zepicpUTmu3gKLHiQHT-zNzh2hRGjBhevoB0:1'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:AA'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\xff')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:qBAK5qoZQNC2Y7sxzUZhQuu9vVGHExuS2TgYmHgy64k:1'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:_w'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\xfe\xff')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:8ZdpKBDUV-KX_OnFZTsCWB_5mlCFI3DynX5f5H2dN-Y:2'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:_v8'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\xff\xfe')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:s9UQ7wQnXKjmmOWzy7Ds45Se-SUvDNyDnp7jR0CaIgk:2'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:__4'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\x00\xff')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:But9amnuGeX733SQGNPSq_oEvL0TZdsxLrhtxxaTibg:2'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:AP8'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\x00\x01')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:tBP0fRPuL-bIRbLuFBr4HehY307FSaWLeXC7lmRbyNI:2'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:AAE'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\x61\x62\x63')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0:3'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:YWJj'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff')
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:ipyQ4jcC1AbAYiuzYDZ1YkAr4O1IxOe5XBKJdJ17nPA:15'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:8fLz9PX29_j5-vv8_f7_'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\x00'*256)
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:U0HmsmRpeacOV2UwB6HzEBaUIeyb3Z8aVkj3Wt4AWvE:256'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:AAAAA...AAAAA'

my_fulfillment = cc.PreimageSha256Fulfillment(b'\xff'*256)
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:PWh2oBRt6FdusjlahY3hIT0bksZbd53zozHP1aRYRUY:256'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:_____...____w'

my_fulfillment = cc.PreimageSha256Fulfillment(array.array('B', range(256)).tostring())
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:QK_y6dLYki5Hr9RkjmlnSXFYeF-9Hahw5xECZr-USIA:256'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:AAECAwQFBgcICQoLDA0...jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w'

my_fulfillment = cc.PreimageSha256Fulfillment(array.array('B', range(256)).tostring()*16)
print(my_fulfillment.condition_uri)
# prints 'cc:0:3:yPXQNB1U2VGnGxNubir8sU0R7YSJp64Sao_uDfbs8ZM:4096'
print(my_fulfillment.serialize_uri())
# prints 'cf:0:AAECAwQFBgcICQoLDA0...jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w'

condition_uri = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
parsed_condition = cc.Condition.from_uri(condition_uri)
print(parsed_condition.__class__.__name__)
# prints 'Condition'
print(parsed_condition.serialize_uri())
# prints condition_uri


fulfillment_uri = 'cf:0:8fLz9PX29_j5-vv8_f7_'
parsed_fulfillment = cc.Fulfillment.from_uri(fulfillment_uri)
print(parsed_fulfillment.__class__.__name__)
# prints 'Fulfillment'
print(parsed_fulfillment.serialize_uri())
# prints fulfillment_uri

my_condition = cc.Condition()
my_condition.type_id = cc.PreimageSha256Fulfillment.TYPE_ID
my_condition.bitmask = cc.PreimageSha256Fulfillment.FEATURE_BITMASK
my_condition.hash = binascii.unhexlify('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
my_condition.max_fulfillment_length = 0
print(my_condition.serialize_uri())
