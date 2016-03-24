
import pytest

# ED25519
VK_HEX_ILP = b'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf'
VK_B64_ILP = b'7Bcrk61eVjv0kyxw4SRQNMNUZ+8u/U1k6/gZaDRn4r8'
VK_B58_ILP = b'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU'
VK_BYT_ILP = b'\xec\x17+\x93\xad^V;\xf4\x93,p\xe1$P4\xc3Tg\xef.\xfdMd\xeb\xf8\x19h4g\xe2\xbf'

VK_B64_ILP_2 = b'Lvf3YtnHLMER+VHT0aaeEJF+7WQcvp4iKZAdvMVto7c'

SK_HEX_ILP = b'833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42'
SK_B64_ILP = b'gz/mJAkje51i7HdYdSCRHpp1nOwdGXVbfakBuW3KPUI'
SK_B58_ILP = b'9qLvREC54mhKYivr88VpckyVWdAFmifJpGjbvV5AiTRs'
SK_BYT_ILP = b'\x83?\xe6$\t#{\x9db\xecwXu \x91\x1e\x9au\x9c\xec\x1d\x19u[}\xa9\x01\xb9m\xca=B'

MSG_SHA_ILP = 'claZQU7qkFz7smkAVtQp9ekUCc5LgoeN9W3RItIzykNEDbGSvzeHvOk9v/vrPpm+XWx5VFjd/sVbM2SLnCpxLw=='
SIG_B64_ILP = 'sd0RahwuJJgeNfg8HvWHtYf4uqNgCOqIbseERacqs8G0kXNQQnhfV6gWAnMb+0RIlY3e0mqbrQiUwbRYJvRBAw=='

# ECDSA
SK_VALUE_ECDSA = 64328150571824492670917070117568709277186368319388887463636481841106388379832
SK_B58_ECDSA = 'AaAp4xBavbe6VGeQF2mWdSKNM1r6HfR2Z1tAY6aUkwdq'

VK_VALUE_X_ECDSA = 48388170575736684074633245566225141536152842355597159440179742847497614196929
VK_VALUE_Y_ECDSA = 65233479152484407841598798165960909560839872511163322973341535484598825150846
VK_B58_ECDSA = 'ifEi3UuTDT4CqUUKiS5omgeDodhu2aRFHVp6LoahbEVe'

# ILP CRYPTOCONDITIONS
CONDITION_SHA256_URI = 'cc:1:1:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:1'
CONDITION_SHA256_HASH = b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
FULFILLMENT_SHA256_URI = 'cf:1:1:AA'

CONDITION_ED25519_URI = 'cc:1:8:qQINW2um59C4DB9JSVXH1igqAmaYGGqryllHUgCpfPU:113'
CONDITION_ED25519_HASH = b'a9020d5b6ba6e7d0b80c1f494955c7d6282a026698186aabca59475200a97cf5'
FULFILLMENT_ED25519_URI = \
    'cf:1:8:IOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_DEhlbGxvIHdvcmxkISAVIENvbmRpdGlvbnMgYXJlIGhlcmUhQENbql531' \
    'PbCJlRUvKjP56k0XKJMOrIGo2F66ueuTtRnYrJB2t2ZttdfXM4gzD_87eH1nZTpu4rTkAx81hSdpwI'

CONDITION_ED25519_URI_2 = 'cc:1:8:_WzTrHvFnv4I-H0cAKWZ6Q3g3Y0Du3aW01nIsaAsio8:116'
CONDITION_ED25519_HASH_2 = b'a9020d5b6ba6e7d0b80c1f494955c7d6282a026698186aabca59475200a97cf5'
FULFILLMENT_ED25519_URI_2 = \
    'cf:1:8:IOwXK5OtXlY79JMscOEkUDTDVGfvLv1NZOv4GWg0Z-K_D0hlbGxvIHVuaXZlcnNlISAbIENvbmRpdGlvbnMgYXJlIGV2ZXJ5d2hlc' \
    'mUhQNmD2Cvk7e3EFOo-arA2TKYTP-474Z4okhbYmKij6XxObIbRsDScjXILAJ6mV5hP7Xyqkg5fcSsZbfRYypzlsAM'

CONDITION_THRESHOLD_ED25519_URI = 'cc:1:d:fDM51fekeLlbeF9yj9W1KT76jtqa7u0vMlJAbM4EyiE:230'
FULFILLMENT_THRESHOLD_ED25519_URI = \
    'cf:1:4:AgIBAQABCCDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfivwxIZWxsbyB3b3JsZCEgFSBDb25kaXRpb25zIGFyZSBoZXJlI' \
    'UBDW6ped9T2wiZUVLyoz-epNFyiTDqyBqNheurnrk7UZ2KyQdrdmbbXX1zOIMw__O3h9Z2U6buK05AMfNYUnacCAQEIIP1s06x7xZ7-CPh9H' \
    'AClmekN4N2NA7t2ltNZyLGgLIqPdA'


@pytest.fixture(scope='module')
def vk_ilp():
    return {
        'hex': VK_HEX_ILP,
        'b64': VK_B64_ILP,
        'b58': VK_B58_ILP,
        'byt': VK_BYT_ILP,
        2: {
           'b64': VK_B64_ILP_2
        }
    }


@pytest.fixture(scope='module')
def sk_ilp():
    return {
        'hex': SK_HEX_ILP,
        'b64': SK_B64_ILP,
        'b58': SK_B58_ILP,
        'byt': SK_BYT_ILP
    }


@pytest.fixture(scope='module')
def signature():
    return {
        'msg': MSG_SHA_ILP,
        'sig': SIG_B64_ILP
    }


@pytest.fixture(scope='module')
def vk_ecdsa():
    return {
        'b58': VK_B58_ECDSA,
        'value_x': VK_VALUE_X_ECDSA,
        'value_y': VK_VALUE_Y_ECDSA,
    }


@pytest.fixture(scope='module')
def sk_ecdsa():
    return {
        'b58': SK_B58_ECDSA,
        'value': SK_VALUE_ECDSA
    }


@pytest.fixture(scope='module')
def fulfillment_sha256():
    return {
        'condition_uri': CONDITION_SHA256_URI,
        'condition_hash': CONDITION_SHA256_HASH,
        'fulfillment_uri': FULFILLMENT_SHA256_URI
    }


@pytest.fixture(scope='module')
def fulfillment_ed25519():
    return {
        'condition_uri': CONDITION_ED25519_URI,
        'condition_hash': CONDITION_ED25519_HASH,
        'fulfillment_uri': FULFILLMENT_ED25519_URI
    }


@pytest.fixture(scope='module')
def fulfillment_ed25519_2():
    return {
        'condition_uri': CONDITION_ED25519_URI_2,
        'condition_hash': CONDITION_ED25519_HASH_2,
        'fulfillment_uri': FULFILLMENT_ED25519_URI_2
    }


@pytest.fixture(scope='module')
def fulfillment_threshold():
    return {
        'condition_uri': CONDITION_THRESHOLD_ED25519_URI,
        'condition_hash': None,
        'fulfillment_uri': FULFILLMENT_THRESHOLD_ED25519_URI
    }
