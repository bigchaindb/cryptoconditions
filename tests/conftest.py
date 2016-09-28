
import pytest

# ED25519
VK_HEX_ILP = b'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf'
VK_B64_ILP = b'7Bcrk61eVjv0kyxw4SRQNMNUZ+8u/U1k6/gZaDRn4r8='
VK_B58_ILP = b'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU'
VK_BYT_ILP = b'\xec\x17+\x93\xad^V;\xf4\x93,p\xe1$P4\xc3Tg\xef.\xfdMd\xeb\xf8\x19h4g\xe2\xbf'


SK_HEX_ILP = b'833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42'
SK_B64_ILP = b'gz/mJAkje51i7HdYdSCRHpp1nOwdGXVbfakBuW3KPUI='
SK_B58_ILP = b'9qLvREC54mhKYivr88VpckyVWdAFmifJpGjbvV5AiTRs'
SK_BYT_ILP = b'\x83?\xe6$\t#{\x9db\xecwXu \x91\x1e\x9au\x9c\xec\x1d\x19u[}\xa9\x01\xb9m\xca=B'

SK_HEX_ILP_2 = b'1a3ab1a87f000348f391613930cc49529652ecf2d2c7cadfd96e87a7f6de948a'
SK_B58_ILP_2 = b'2mPWYbfDE2HrUaisDViseCLDcshYeRiJzR2XYkfmiK4m'

VK_HEX_ILP_2 = b'a614d63a28be3e8e45ea99638d22abc0430e4112a28b3f601a617f9c7f445021'
VK_B58_ILP_2 = b'CBK79fAE8AVxwprPumyLrW5JfHaDRAReSpmsg92FV3GL'
VK_B64_ILP_2 = b'phTWOii+Po5F6pljjSKrwEMOQRKiiz9gGmF/nH9EUCE='

MSG_SHA_ILP = 'claZQU7qkFz7smkAVtQp9ekUCc5LgoeN9W3RItIzykNEDbGSvzeHvOk9v/vrPpm+XWx5VFjd/sVbM2SLnCpxLw=='
SIG_B64_ILP = 'ZAg/R++Z3yhggpW8iviqdDwhhV0nK6et/Nn66Hcds9rSk3f4JDsNHws1dMsbqY6KKuToxwvDuDmzW3a8JVqwBg=='

# ILP CRYPTOCONDITIONS
CONDITION_SHA256_URI = 'cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0'
CONDITION_SHA256_HASH = b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
FULFILLMENT_SHA256_URI = 'cf:0:'

CONDITION_ED25519_URI = 'cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96'
CONDITION_ED25519_HASH = b'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf'
FULFILLMENT_ED25519_URI = \
    'cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisH' \
    'OyGpR1FISer26CdG28zHAcK'

CONDITION_ED25519_URI_2 = 'cc:4:20:phTWOii-Po5F6pljjSKrwEMOQRKiiz9gGmF_nH9EUCE:96'
CONDITION_ED25519_HASH_2 = b'a614d63a28be3e8e45ea99638d22abc0430e4112a28b3f601a617f9c7f445021'
FULFILLMENT_ED25519_URI_2 = \
    'cf:4:phTWOii-Po5F6pljjSKrwEMOQRKiiz9gGmF_nH9EUCEXkJ3NhSGXDidLJME_Pcg9Qp7rFaQmk9JSP7DfOEWl7Ml06AgVUDfMTmd8DiRMx' \
    'DYY2CDq45hUlTXYvJoOCaEF'

CONDITION_THRESHOLD_SHA_ED25519_URI = 'cc:2:2b:mJUaGKCuF5n-3tfXM2U81VYtHbX-N8MP6kz8R-ASwNQ:146'
FULFILLMENT_THRESHOLD_SHA_ED25519_URI = 'cf:2:AQEBAgEBAwAAAAABAQAnAAQBICDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfivwFg'

CONDITION_NESTED_AND_OR_URI = 'cc:2:2b:ytUyoE7fu1QzQMCDpx9xxi09ojfL_vbykvtJZsI0JEE:161'
FULFILLMENT_NESTED_AND_OR_URI = 'cf:2:AQIBAgEBAwAAAAABAYGaAAKBlgEBAQIBAQAnAAQBICDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-' \
                                'BloNGfivwFgAQFjAARg7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldv' \
                                'ik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcKAAA'


@pytest.fixture(scope='module')
def vk_ilp():
    return {
        'hex': VK_HEX_ILP,
        'b64': VK_B64_ILP,
        'b58': VK_B58_ILP,
        'byt': VK_BYT_ILP,
        2: {
            'hex': VK_HEX_ILP_2,
            'b64': VK_B64_ILP_2,
            'b58': VK_B58_ILP_2
        }
    }


@pytest.fixture(scope='module')
def sk_ilp():
    return {
        'hex': SK_HEX_ILP,
        'b64': SK_B64_ILP,
        'b58': SK_B58_ILP,
        'byt': SK_BYT_ILP,
        2: {
            'hex': SK_HEX_ILP_2,
            'b58': SK_B58_ILP_2
        }
    }


@pytest.fixture(scope='module')
def signature():
    return {
        'msg': MSG_SHA_ILP,
        'sig': SIG_B64_ILP
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
        'condition_uri': CONDITION_THRESHOLD_SHA_ED25519_URI,
        'condition_hash': None,
        'fulfillment_uri': FULFILLMENT_THRESHOLD_SHA_ED25519_URI
    }


@pytest.fixture(scope='module')
def fulfillment_threshold_nested_and_or():
    return {
        'condition_uri': CONDITION_NESTED_AND_OR_URI,
        'condition_hash': None,
        'fulfillment_uri': FULFILLMENT_NESTED_AND_OR_URI
    }
