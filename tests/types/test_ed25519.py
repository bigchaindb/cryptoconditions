from pytest import mark, raises


class TestEd25519Sha256:

    def test_init(self):
        from cryptoconditions.types.ed25519 import Ed25519Sha256
        ed25519 = Ed25519Sha256()
        assert ed25519.public_key is None
        assert ed25519.signature is None

    @mark.parametrize('public_key', (123, 'abc'))
    def test_init_with_public_key_not_in_bytes(self, public_key):
        from cryptoconditions.types.ed25519 import Ed25519Sha256
        with raises(TypeError) as exc:
            Ed25519Sha256(public_key=public_key)
        assert exc.value.args == ('public_key must be bytes',)

    @mark.parametrize('public_key', (b'123', b'a' * 33))
    def test_init_with_public_key_improper_length(self, public_key):
        from cryptoconditions.types.ed25519 import Ed25519Sha256
        with raises(ValueError) as exc:
            Ed25519Sha256(public_key=public_key)
        assert exc.value.args == (
            'Public key must be {} bytes, was: {}'.format(
                Ed25519Sha256.PUBLIC_KEY_LENGTH, len(public_key)),)
