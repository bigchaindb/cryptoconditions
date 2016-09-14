import binascii
import base58
import base64

from cryptoconditions.crypto import \
    Ed25519SigningKey as SigningKey, \
    Ed25519VerifyingKey as VerifyingKey, \
    ed25519_generate_key_pair, base64_add_padding


class TestBigchainCryptoED25519(object):

    def test_signing_key_encode(self, sk_ilp):
        sk = SigningKey(base64_add_padding(sk_ilp['b64']), encoding='base64')
        private_value_base58 = sk.encode(encoding="base58")
        assert private_value_base58 == sk_ilp['b58']

    def test_signing_key_init(self, sk_ilp):
        sk = SigningKey(sk_ilp['b58'])
        assert sk.encode(encoding='base64') == sk_ilp['b64']
        assert sk.to_seed() == sk_ilp['byt']

    def test_signing_key_decode(self, sk_ilp):
        private_value = SigningKey.decode(sk_ilp['b58'])
        assert private_value == base64_add_padding(sk_ilp['b64'])

    def test_verifying_key_encode(self, vk_ilp):
        public_value_base58 = VerifyingKey.encode(base64_add_padding(vk_ilp['b64']))
        assert public_value_base58 == vk_ilp['b58']

    def test_verifying_key_init(self, vk_ilp):
        vk = VerifyingKey(vk_ilp['b58'])
        assert vk.to_ascii(encoding='base64') == vk_ilp['b64']
        assert vk.to_bytes() == vk_ilp['byt']

    def test_verifying_key_decode(self, vk_ilp):
        public_value = VerifyingKey.decode(vk_ilp['b58'])
        assert public_value == base64_add_padding(vk_ilp['b64'])

    def test_sign_verify(self, sk_ilp, vk_ilp):
        message = 'Hello World!'
        sk = SigningKey(sk_ilp['b58'])
        vk = VerifyingKey(vk_ilp['b58'])
        assert vk.verify(message, sk.sign(message)) is True
        assert vk.verify(message, sk.sign(message + 'dummy')) is False
        assert vk.verify(message + 'dummy', sk.sign(message)) is False
        vk = VerifyingKey(
            VerifyingKey.encode(
                base64_add_padding(vk_ilp[2]['b64'])))
        assert vk.verify(message, sk.sign(message)) is False

    def test_to_ascii(self, sk_ilp, vk_ilp):
        sk = SigningKey(sk_ilp['b58'])
        assert sk.to_ascii(encoding='base58') == sk_ilp['b58']
        assert sk.to_ascii(encoding='base64') == sk_ilp['b64']
        vk = VerifyingKey(vk_ilp['b58'])
        assert vk.to_ascii(encoding='base58') == vk_ilp['b58']
        assert vk.to_ascii(encoding='base64') == vk_ilp['b64']

    def test_get_verifying_key(self, sk_ilp, vk_ilp):
        sk = SigningKey(sk_ilp['b58'])
        vk = VerifyingKey(vk_ilp['b58'])
        vk_from_sk = sk.get_verifying_key()
        assert vk.to_bytes() == vk_from_sk.to_bytes()

    def test_valid_condition_valid_signature_ilp(self, vk_ilp, signature):
        vk = VerifyingKey(
            VerifyingKey.encode(
                base64_add_padding(vk_ilp[2]['b64'])))
        msg = base64.b64decode(signature['msg'])
        assert vk.verify(msg, signature['sig'], encoding='base64') is True
        assert vk.verify(msg, binascii.hexlify(base64.b64decode(signature['sig'])), encoding='hex') is True
        assert vk.verify(msg, base64.b64decode(signature['sig']), encoding=None) is True

    def test_valid_condition_invalid_signature_ilp(self, vk_ilp, signature):
        vk = VerifyingKey(
            VerifyingKey.encode(
                base64_add_padding(vk_ilp[2]['b64'])))
        msg = base64.b64decode(signature['msg'])
        assert vk.verify(msg, signature['msg'], encoding='base64') is False
        assert vk.verify(msg, binascii.hexlify(base64.b64decode(signature['msg'])), encoding='hex') is False
        assert vk.verify(msg, base64.b64decode(signature['msg']), encoding=None) is False

    def test_generate_key_pair(self):
        sk_b58, vk_b58 = ed25519_generate_key_pair()
        assert len(base58.b58decode(sk_b58)) == 32
        assert len(base58.b58decode(vk_b58)) == 32
        assert SigningKey.encode(SigningKey.decode(sk_b58)) == sk_b58
        assert VerifyingKey.encode(VerifyingKey.decode(vk_b58)) == vk_b58

    def test_generate_sign_verify(self, vk_ilp):
        sk_b58, vk_b58 = ed25519_generate_key_pair()
        sk = SigningKey(sk_b58)
        vk = VerifyingKey(vk_b58)
        message = 'Hello World!'
        assert vk.verify(message, sk.sign(message)) is True
        assert vk.verify(message, sk.sign(message + 'dummy')) is False
        assert vk.verify(message + 'dummy', sk.sign(message)) is False
        vk = VerifyingKey(
            VerifyingKey.encode(
                base64_add_padding(vk_ilp[2]['b64'])))
        assert vk.verify(message, sk.sign(message)) is False

    def test_weak_public_keys(self):
        """reproduce the problem in https://github.com/bigchaindb/bigchaindb/issues/617

        This problem is due to weak keys, specially in this case the key and signature 
        when decoded from base58 correspond to a key and a signature that are zero.
        In this case its possible to come up with messages that would verify.

        Libraries like libsodium check for these weak keys and return a BadSignature error
        if weak keys are being used.

        More details here: https://github.com/jedisct1/libsodium/issues/112
        """
        vk_b58 = VerifyingKey('1' * 32)
        message = 'age=33&name=luo&title=architecture'
        signature = '1' * 64
        assert vk_b58.verify(message, signature) == False
