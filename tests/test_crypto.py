import binascii
import base58
import base64

from cryptoconditions.buffer import base64_add_padding
from cryptoconditions.ecdsa import EcdsaSigningKey, EcdsaVerifyingKey, ecdsa_generate_key_pair
from cryptoconditions.ed25519 import Ed25519SigningKey, Ed25519VerifyingKey, ed25519_generate_key_pair


class TestBigchainCryptoED25519(object):

    def test_signing_key_encode(self, sk_ilp):
        private_value_base58 = Ed25519SigningKey.encode(base64_add_padding(sk_ilp['b64']))
        assert private_value_base58 == sk_ilp['b58']

    def test_signing_key_init(self, sk_ilp):
        sk = Ed25519SigningKey(sk_ilp['b58'])
        assert sk.to_ascii(encoding='base64') == sk_ilp['b64']
        assert sk.to_seed() == sk_ilp['byt']

    def test_signing_key_decode(self, sk_ilp):
        private_value = Ed25519SigningKey.decode(sk_ilp['b58'])
        assert private_value == base64_add_padding(sk_ilp['b64'])

    def test_verifying_key_encode(self, vk_ilp):
        public_value_base58 = Ed25519VerifyingKey.encode(base64_add_padding(vk_ilp['b64']))
        assert public_value_base58 == vk_ilp['b58']

    def test_verifying_key_init(self, vk_ilp):
        vk = Ed25519VerifyingKey(vk_ilp['b58'])
        assert vk.to_ascii(encoding='base64') == vk_ilp['b64']
        assert vk.to_bytes() == vk_ilp['byt']

    def test_verifying_key_decode(self, vk_ilp):
        public_value = Ed25519VerifyingKey.decode(vk_ilp['b58'])
        assert public_value == base64_add_padding(vk_ilp['b64'])

    def test_sign_verify(self, sk_ilp, vk_ilp):
        message = 'Hello World!'
        sk = Ed25519SigningKey(sk_ilp['b58'])
        vk = Ed25519VerifyingKey(vk_ilp['b58'])
        assert vk.verify(message, sk.sign(message)) is True
        assert vk.verify(message, sk.sign(message + 'dummy')) is False
        assert vk.verify(message + 'dummy', sk.sign(message)) is False
        vk = Ed25519VerifyingKey(
            Ed25519VerifyingKey.encode(
                base64_add_padding(vk_ilp[2]['b64'])))
        assert vk.verify(message, sk.sign(message)) is False

    def test_to_ascii(self, sk_ilp, vk_ilp):
        sk = Ed25519SigningKey(sk_ilp['b58'])
        assert sk.to_ascii(encoding='base58') == sk_ilp['b58']
        assert sk.to_ascii(encoding='base64') == sk_ilp['b64']
        vk = Ed25519VerifyingKey(vk_ilp['b58'])
        assert vk.to_ascii(encoding='base58') == vk_ilp['b58']
        assert vk.to_ascii(encoding='base64') == vk_ilp['b64']

    def test_get_verifying_key(self, sk_ilp, vk_ilp):
        sk = Ed25519SigningKey(sk_ilp['b58'])
        vk = Ed25519VerifyingKey(vk_ilp['b58'])
        vk_from_sk = sk.get_verifying_key()
        assert vk.to_bytes() == vk_from_sk.to_bytes()

    def test_valid_condition_valid_signature_ilp(self, vk_ilp, signature):
        vk = Ed25519VerifyingKey(
            Ed25519VerifyingKey.encode(
                base64_add_padding(vk_ilp[2]['b64'])))
        msg = base64.b64decode(signature['msg'])
        assert vk.verify(msg, signature['sig'], encoding='base64') is True
        assert vk.verify(msg, binascii.hexlify(base64.b64decode(signature['sig'])), encoding='hex') is True
        assert vk.verify(msg, base64.b64decode(signature['sig']), encoding=None) is True

    def test_valid_condition_invalid_signature_ilp(self, vk_ilp, signature):
        vk = Ed25519VerifyingKey(
            Ed25519VerifyingKey.encode(
                base64_add_padding(vk_ilp[2]['b64'])))
        msg = base64.b64decode(signature['msg'])
        assert vk.verify(msg, signature['msg'], encoding='base64') is False
        assert vk.verify(msg, binascii.hexlify(base64.b64decode(signature['msg'])), encoding='hex') is False
        assert vk.verify(msg, base64.b64decode(signature['msg']), encoding=None) is False

    def test_generate_key_pair(self):
        sk_b58, vk_b58 = ed25519_generate_key_pair()
        assert len(base58.b58decode(sk_b58)) == 32
        assert len(base58.b58decode(vk_b58)) == 32
        assert Ed25519SigningKey.encode(Ed25519SigningKey.decode(sk_b58)) == sk_b58
        assert Ed25519VerifyingKey.encode(Ed25519VerifyingKey.decode(vk_b58)) == vk_b58

    def test_generate_sign_verify(self, vk_ilp):
        sk_b58, vk_b58 = ed25519_generate_key_pair()
        sk = Ed25519SigningKey(sk_b58)
        vk = Ed25519VerifyingKey(vk_b58)
        message = 'Hello World!'
        assert vk.verify(message, sk.sign(message)) is True
        assert vk.verify(message, sk.sign(message + 'dummy')) is False
        assert vk.verify(message + 'dummy', sk.sign(message)) is False
        vk = Ed25519VerifyingKey(
            Ed25519VerifyingKey.encode(
                base64_add_padding(vk_ilp[2]['b64'])))
        assert vk.verify(message, sk.sign(message)) is False


class TestBigchainCryptoECDSA(object):

    def test_signing_key_encode(self, sk_ecdsa):
        assert EcdsaSigningKey.encode(sk_ecdsa['value']) == sk_ecdsa['b58']

    def test_signing_key_decode(self, sk_ecdsa):
        assert EcdsaSigningKey.decode(sk_ecdsa['b58']) == sk_ecdsa['value']

    def test_verifying_key_encode(self, vk_ecdsa):
        assert EcdsaVerifyingKey.encode(vk_ecdsa['value_x'], vk_ecdsa['value_y']) == vk_ecdsa['b58']

    def test_verifying_key_decode(self, vk_ecdsa):
        sk_value_x, sk_value_y = EcdsaVerifyingKey.decode(vk_ecdsa['b58'])
        assert sk_value_x == vk_ecdsa['value_x']
        assert sk_value_y == vk_ecdsa['value_y']

    def test_sign_verify(self, vk_ecdsa, sk_ecdsa):
        message = 'Hello World!'
        vk = EcdsaVerifyingKey(vk_ecdsa['b58'])
        sk = EcdsaSigningKey(sk_ecdsa['b58'])
        assert vk.verify(message, sk.sign(message)) is True

    def test_generate_key_pair(self):
        sk_b58, vk_b58 = ecdsa_generate_key_pair()
        assert EcdsaSigningKey.encode(
            EcdsaSigningKey.decode(sk_b58)) == sk_b58
        assert EcdsaVerifyingKey.encode(
            *EcdsaVerifyingKey.decode(vk_b58)) == vk_b58
