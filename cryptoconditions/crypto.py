# Separate all crypto code so that we can easily test several implementations
import base64
import base58
import nacl.signing
import nacl.encoding
import nacl.exceptions

from cryptoconditions import exceptions


class Base58Encoder(object):

    @staticmethod
    def encode(data):
        return base58.b58encode(data)

    @staticmethod
    def decode(data):
        return base58.b58decode(data)


def _get_nacl_encoder(encoding):
    if encoding == 'base58':
        return Base58Encoder
    elif encoding == 'base64':
        return nacl.encoding.Base64Encoder
    elif encoding == 'base32':
        return nacl.encoding.Base32Encoder
    elif encoding == 'base16':
        return nacl.encoding.Base16Encoder
    elif encoding == 'hex':
        return nacl.encoding.HexEncoder
    elif encoding is 'bytes':
        return nacl.encoding.RawEncoder
    else:
        raise exceptions.UnknownEncodingError("Unknown or unsupported encoding")


class Ed25519SigningKey(nacl.signing.SigningKey):
    """
    PrivateKey instance
    """

    def __init__(self, key, encoding='base58'):
        """
        Instantiate the private key with the private value.

        Args:
            key (str): encoded private value.
            encoding(str): {'bytes'|'hex'|'base16'|'base32'|'base58'|'base64'}. Encoding of the private
                           value. Defaults to 'base58'.
        """
        super().__init__(key, encoder=_get_nacl_encoder(encoding))

    def get_verifying_key(self):
        """
        Get the corresponding VerifyingKey

        Returns:
            Ed25519VerifyingKey
        """
        return Ed25519VerifyingKey(self.verify_key.encode(encoder=Base58Encoder))

    def sign(self, data, encoding='base58'):
        """
        Sign data with private key

        Args:
            data (bytes): data to sign.
            encoding(str): {'bytes'|'hex'|'base16'|'base32'|'base58'|'base64'}. Encoding in which to return the
                           signature. Defaults to 'base58'.

            Returns:
                The signature encoded in `encoding`.
        """
        raw_signature = super().sign(data).signature
        return _get_nacl_encoder(encoding).encode(raw_signature)

    def encode(self, encoding='base58'):
        """
        Encode the private key

        Args:
            encoding(str): {'bytes'|'hex'|'base16'|'base32'|'base58'|'base64'}. Encoding in which the private
                           key should be returned. Defaults to 'base58'.

        Returns:
            The private key encoded with `encoding`.
        """
        return super().encode(encoder=_get_nacl_encoder(encoding))

    @classmethod
    def generate(cls):
        return cls(nacl.signing.SigningKey.generate().encode(encoder=Base58Encoder))
    
    @classmethod
    def generate_with_seed(cls, seed):
        return cls(nacl.signing.SigningKey(seed).encode(encoder=Base58Encoder))


class Ed25519VerifyingKey(nacl.signing.VerifyKey):

    def __init__(self, key, encoding='base58'):
        """
        Instantiate the public key with the public value.

        Args:
            key (str): encoded compressed value.
            encoding(str): {'bytes'|'hex'|'base16'|'base32'|'base58'|'base64'}. Encoding of the public key.
                           Defaults to 'base58'.
        """
        super().__init__(key, encoder=_get_nacl_encoder(encoding))

    def verify(self, data, signature, encoding='base58'):
        """
        Verify if the signature signs the data with this verifying key

        Args:
            data (bytes): data to verify.
            signature (bytes): {base64|base32|base16|hex|bytes} signature to be verified
            encoding(str): {'bytes'|'hex'|'base16'|'base32'|'base58'|'base64'}. Encoding of the signature.
                           Defaults to 'base58'.
        """

        # The reason for using raw_signatures here is because the verify method of pynacl expects the message
        # and the signature to have the same encoding. Basically pynacl does:
        #   encoder.decode(signature + message)
        raw_signature = _get_nacl_encoder(encoding).decode(signature)
        try:
            super().verify(data, raw_signature)
        except nacl.exceptions.BadSignatureError:
            return False

        return True

    def encode(self, encoding='base58'):
        """
        Encode the public key

        Args:
            encoding(str): {'bytes'|'hex'|'base16'|'base32'|'base58'|'base64'}. Encoding in which the public
                           key should be returned. Defaults to 'base58'.

        Returns:
            The public key encoded with `encoding`.
        """
        return super().encode(encoder=_get_nacl_encoder(encoding))


def ed25519_generate_key_pair(seed=None):
    """
    Generate a new key pair.

    Args:
        seed (bytes): 32-byte seed for deterministic generation.
    Returns:
        A tuple of (private_key, public_key) encoded in base58.
    """
    if seed:
        sk = Ed25519SigningKey.generate_with_seed(seed)
    else:
        sk = Ed25519SigningKey.generate()
    # Private key
    private_value_base58 = sk.encode(encoding='base58')

    # Public key
    public_value_compressed_base58 = sk.get_verifying_key().encode(encoding='base58')

    return private_value_base58, public_value_compressed_base58


def base64_add_padding(data):
    """
    Add enough padding for base64 encoding such that length is a multiple of 4

    Args:
        data: unpadded string or bytes
    Return:
        bytes: The padded bytes

    """

    if isinstance(data, str):
        data = data.encode('utf-8')
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += b'=' * missing_padding
    return data


def base64_remove_padding(data):
    """
    Remove padding from base64 encoding

    Args:
        data: fully padded base64 data
    Return:
        base64: Unpadded base64 bytes

    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return data.rstrip(b'=')
