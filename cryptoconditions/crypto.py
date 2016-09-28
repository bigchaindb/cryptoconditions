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
        return base58.b58encode(data).encode()

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
        Instantiate the private key with the private_value encoded in base58

        Args:
            key (base58): base58 encoded private key
        """
        super().__init__(key, encoder=_get_nacl_encoder(encoding))

    def get_verifying_key(self):
        """
        Get the corresponding VerifyingKey

        Returns:
            Ed25519VerifyingKey
        """
        return Ed25519VerifyingKey(self.verify_key.encode(encoder=Base58Encoder))

    def sign(self, data, encoding="base58"):
        """
        Sign data with private key

        Args:
            data (str, bytes): data to sign
            encoding (str): base64, hex
        """
        raw_signature = super().sign(data).signature
        return _get_nacl_encoder(encoding).encode(raw_signature)

    def encode(self, encoding='base58'):
        return super().encode(encoder=_get_nacl_encoder(encoding))


class Ed25519VerifyingKey(nacl.signing.VerifyKey):

    def __init__(self, key, encoding='base58'):
        """
        Instantiate the public key with the compressed public value encoded in base58
        """
        super().__init__(key, encoder=_get_nacl_encoder(encoding))

    def verify(self, data, signature, encoding='base58'):
        """
        Verify if the signature signs the data with this verifying key

        Args:
             data (bytes|str): data verify
             signature (bytes|str): {base64|base32|base16|hex|bytes} signature to be verified
             encoding: {base64|base32|base16|hex|bytes} encoding of the signature
        """
        try:
            # The reason for using raw_signatures here is because the verify method of pynacl expects the message
            # and the signature to have the same encoding. Basically pynacl does:
            #   encoder.decode(signature + message)
            raw_signature = _get_nacl_encoder(encoding).decode(signature)
            super().verify(data, raw_signature)
        except nacl.exceptions.BadSignatureError:
            return False

        return True

    def encode(self, encoding='base58'):
        return super().encode(encoder=_get_nacl_encoder(encoding))


def ed25519_generate_key_pair():
    """
    Generate a new key pair and return the pair encoded in base58
    """
    sk = nacl.signing.SigningKey.generate()
    # Private key
    private_value_base58 = sk.encode(encoder=Base58Encoder)

    # Public key
    public_value_compressed_base58 = sk.verify_key.encode(encoder=Base58Encoder)

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
