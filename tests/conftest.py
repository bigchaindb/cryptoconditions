import json
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import unhexlify
from collections import namedtuple

import pytest

LOCAL_TEST_VECTOR_JSON = "tests/vectors/{}.json"


# ED25519
VK_HEX_ILP = b"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"  # noqa E501
VK_B64_ILP = b"7Bcrk61eVjv0kyxw4SRQNMNUZ+8u/U1k6/gZaDRn4r8="
VK_B58_ILP = b"Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU"
VK_BYT_ILP = b"\xec\x17+\x93\xad^V;\xf4\x93,p\xe1$P4\xc3Tg\xef.\xfdMd\xeb\xf8\x19h4g\xe2\xbf"  # noqa E501


SK_HEX_ILP = b"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"  # noqa E501
SK_B64_ILP = b"gz/mJAkje51i7HdYdSCRHpp1nOwdGXVbfakBuW3KPUI="
SK_B58_ILP = b"9qLvREC54mhKYivr88VpckyVWdAFmifJpGjbvV5AiTRs"
SK_BYT_ILP = b"\x83?\xe6$\t#{\x9db\xecwXu \x91\x1e\x9au\x9c\xec\x1d\x19u[}\xa9\x01\xb9m\xca=B"  # noqa E501

SK_HEX_ILP_2 = b"1a3ab1a87f000348f391613930cc49529652ecf2d2c7cadfd96e87a7f6de948a"  # noqa E501
SK_B58_ILP_2 = b"2mPWYbfDE2HrUaisDViseCLDcshYeRiJzR2XYkfmiK4m"

VK_HEX_ILP_2 = b"a614d63a28be3e8e45ea99638d22abc0430e4112a28b3f601a617f9c7f445021"  # noqa E501
VK_B58_ILP_2 = b"CBK79fAE8AVxwprPumyLrW5JfHaDRAReSpmsg92FV3GL"
VK_B64_ILP_2 = b"phTWOii+Po5F6pljjSKrwEMOQRKiiz9gGmF/nH9EUCE="

MSG_SHA_ILP = "claZQU7qkFz7smkAVtQp9ekUCc5LgoeN9W3RItIzykNEDbGSvzeHvOk9v/vrPpm+XWx5VFjd/sVbM2SLnCpxLw=="  # noqa E501
SIG_B64_ILP = "ZAg/R++Z3yhggpW8iviqdDwhhV0nK6et/Nn66Hcds9rSk3f4JDsNHws1dMsbqY6KKuToxwvDuDmzW3a8JVqwBg=="  # noqa E501

# ILP CRYPTOCONDITIONS
CONDITION_SHA256_URI = "cc:0:3:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU:0"
CONDITION_SHA256_HASH = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # noqa E501
FULFILLMENT_SHA256_URI = "cf:0:"

CONDITION_ED25519_URI = "cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96"  # noqa E501
CONDITION_ED25519_HASH = b"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"  # noqa E501
FULFILLMENT_ED25519_URI = (
    "cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik"
    "_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK"
)

CONDITION_ED25519_URI_2 = "cc:4:20:phTWOii-Po5F6pljjSKrwEMOQRKiiz9gGmF_nH9EUCE:96"  # noqa E501
CONDITION_ED25519_HASH_2 = b"a614d63a28be3e8e45ea99638d22abc0430e4112a28b3f601a617f9c7f445021"  # noqa E501
FULFILLMENT_ED25519_URI_2 = (
    "cf:4:phTWOii-Po5F6pljjSKrwEMOQRKiiz9gGmF_nH9EUCEXkJ3NhSGXDidLJME_Pcg9Qp"
    "7rFaQmk9JSP7DfOEWl7Ml06AgVUDfMTmd8DiRMxDYY2CDq45hUlTXYvJoOCaEF"
)

CONDITION_THRESHOLD_SHA_ED25519_URI = "cc:2:2b:mJUaGKCuF5n-3tfXM2U81VYtHbX-N8MP6kz8R-ASwNQ:146"  # noqa E501
FULFILLMENT_THRESHOLD_SHA_ED25519_URI = (
    "cf:2:AQEBAgEBAwAAAAABAQAnAAQBICDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfivwFg"  # noqa E501
)

CONDITION_NESTED_AND_OR_URI = "cc:2:2b:ytUyoE7fu1QzQMCDpx9xxi09ojfL_vbykvtJZsI0JEE:161"  # noqa E501
FULFILLMENT_NESTED_AND_OR_URI = (
    "cf:2:AQIBAgEBAwAAAAABAYGaAAKBlgEBAQIBAQAnAAQBICDsFyuTrV5WO_STLHDhJFA0w1Rn"
    "7y79TWTr-BloNGfivwFgAQFjAARg7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2I"
    "pH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26"
    "CdG28zHAcKAAA"
)


@pytest.fixture(scope="module")
def vk_ilp():
    return {
        "hex": VK_HEX_ILP,
        "b64": VK_B64_ILP,
        "b58": VK_B58_ILP,
        "byt": VK_BYT_ILP,
        2: {"hex": VK_HEX_ILP_2, "b64": VK_B64_ILP_2, "b58": VK_B58_ILP_2},
    }


@pytest.fixture(scope="module")
def sk_ilp():
    return {
        "hex": SK_HEX_ILP,
        "b64": SK_B64_ILP,
        "b58": SK_B58_ILP,
        "byt": SK_BYT_ILP,
        2: {"hex": SK_HEX_ILP_2, "b58": SK_B58_ILP_2},
    }


@pytest.fixture(scope="module")
def signature():
    return {"msg": MSG_SHA_ILP, "sig": SIG_B64_ILP}


@pytest.fixture(scope="module")
def fulfillment_sha256():
    return {
        "condition_uri": CONDITION_SHA256_URI,
        "condition_hash": CONDITION_SHA256_HASH,
        "fulfillment_uri": FULFILLMENT_SHA256_URI,
    }


@pytest.fixture(scope="module")
def fulfillment_ed25519():
    return {
        "condition_uri": CONDITION_ED25519_URI,
        "condition_hash": CONDITION_ED25519_HASH,
        "fulfillment_uri": FULFILLMENT_ED25519_URI,
    }


@pytest.fixture(scope="module")
def fulfillment_ed25519_2():
    return {
        "condition_uri": CONDITION_ED25519_URI_2,
        "condition_hash": CONDITION_ED25519_HASH_2,
        "fulfillment_uri": FULFILLMENT_ED25519_URI_2,
    }


@pytest.fixture(scope="module")
def fulfillment_threshold():
    return {
        "condition_uri": CONDITION_THRESHOLD_SHA_ED25519_URI,
        "condition_hash": None,
        "fulfillment_uri": FULFILLMENT_THRESHOLD_SHA_ED25519_URI,
    }


@pytest.fixture(scope="module")
def fulfillment_threshold_nested_and_or():
    return {
        "condition_uri": CONDITION_NESTED_AND_OR_URI,
        "condition_hash": None,
        "fulfillment_uri": FULFILLMENT_NESTED_AND_OR_URI,
    }


###############################################################################
#                                                                             #
# TEST VECTORS - MUST match:                                                  #
# https://github.com/rfcs/crypto-conditions/tree/master/test-vectors/valid    #
#                                                                             #
###############################################################################

TestVector = namedtuple(
    "TestVector",
    (
        "subtypes",
        "condition_binary",
        "cost",
        "json",
        "message",
        "fulfillment",
        "condition_uri",
        "fingerprint_contents",
    ),
)


Ed25519TestVector = namedtuple("Ed25519TestVector", TestVector._fields + ("private_key",))


first_cap_re = re.compile("(.)([A-Z][a-z]+)")
all_cap_re = re.compile("([a-z0-9])([A-Z])")


def snake_case(camel_case_string):
    s1 = first_cap_re.sub(r"\1_\2", camel_case_string)
    return all_cap_re.sub(r"\1_\2", s1).lower()


def normalize_value(value, key):
    from planetmint_cryptoconditions.crypto import base64_add_padding, base64_remove_padding

    if key in ("public_key", "signature"):
        value = urlsafe_b64decode(base64_add_padding(value))
    if key in ("condition_binary", "fingerprint_contents", "message"):
        value = unhexlify(value.encode())
    if key == "fulfillment":
        value = base64_remove_padding(urlsafe_b64encode(unhexlify(value.encode()))).decode()
    return value


@pytest.fixture(
    params=(
        "0000_test-minimal-preimage",
        "0001_test-minimal-prefix",
        "0002_test-minimal-threshold",
        "0003_test-minimal-rsa",
        "0004_test-minimal-ed25519",
        "0005_test-basic-preimage",
        "0006_test-basic-prefix",
        "0007_test-basic-prefix-two-levels-deep",
        "0008_test-basic-threshold",
        "0009_test-basic-threshold-same-condition-twice",
        "0010_test-basic-threshold-same-fulfillment-twice",
        "0011_test-basic-threshold-two-levels-deep",
        "0012_test-basic-threshold-schroedinger",
        "0013_test-basic-rsa",
        "0014_test-basic-rsa4096",
        "0015_test-basic-ed25519",
        "0016_test-advanced-notarized-receipt",
        "0017_test-advanced-notarized-receipt-multiple-notaries",
    )
)
def test_vector(request):
    with open(LOCAL_TEST_VECTOR_JSON.format(request.param), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def minimal_preimage():
    vector_name = "0000_test-minimal-preimage"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def minimal_prefix():
    vector_name = "0001_test-minimal-prefix"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def minimal_threshold():
    vector_name = "0002_test-minimal-threshold"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def minimal_rsa():
    vector_name = "0003_test-minimal-rsa"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def minimal_ed25519_private_key_base64url():
    return "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"


@pytest.fixture
def minimal_ed25519_private_key(minimal_ed25519_private_key_base64url):
    from planetmint_cryptoconditions.crypto import base64_add_padding

    return urlsafe_b64decode(base64_add_padding(minimal_ed25519_private_key_base64url))


@pytest.fixture
def minimal_ed25519(minimal_ed25519_private_key):
    vector_name = "0004_test-minimal-ed25519"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    vector = {snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()}
    vector["private_key"] = minimal_ed25519_private_key
    return Ed25519TestVector(**vector)


@pytest.fixture
def basic_preimage():
    vector_name = "0005_test-basic-preimage"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_prefix():
    vector_name = "0006_test-basic-prefix"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_prefix_two_levels_deep():
    vector_name = "0007_test-basic-prefix-two-levels-deep"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_threshold():
    vector_name = "0008_test-basic-threshold"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_threshold_same_condition_twice():
    vector_name = "0009_test-basic-threshold-same-condition-twice"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_threshold_same_fulfillment_twice():
    vector_name = "0010_test-basic-threshold-same-fulfillment-twice"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_threshold_two_levels_deep():
    vector_name = "0011_test-basic-threshold-two-levels-deep"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_threshold_schroedinger():
    vector_name = "0012_test-basic-threshold-schroedinger"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_rsa():
    vector_name = "0013_test-basic-rsa"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_rsa4096():
    vector_name = "0014_test-basic-rsa4096"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def basic_ed25519_private_key_base64url():
    return "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"


@pytest.fixture
def basic_ed25519_private_key(basic_ed25519_private_key_base64url):
    from planetmint_cryptoconditions.crypto import base64_add_padding

    return urlsafe_b64decode(base64_add_padding(basic_ed25519_private_key_base64url))


@pytest.fixture
def basic_ed25519(basic_ed25519_private_key):
    vector_name = "0015_test-basic-ed25519"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    vector = {snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()}
    vector["private_key"] = basic_ed25519_private_key
    return Ed25519TestVector(**vector)


@pytest.fixture
def notarized_receipt():
    vector_name = "0016_test-advanced-notarized-receipt"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})


@pytest.fixture
def notarized_receipt_multiple_notaries():
    vector_name = "0017_test-advanced-notarized-receipt-multiple-notaries"
    with open(LOCAL_TEST_VECTOR_JSON.format(vector_name), "r") as f:
        test_vector = json.load(f)
    return TestVector(**{snake_case(k): normalize_value(v, snake_case(k)) for k, v in test_vector.items()})
