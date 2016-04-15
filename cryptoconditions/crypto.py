# Separate all crypto code so that we can easily test several implementations
from abc import ABCMeta, abstractmethod
import base64

import base58
import ed25519


class SigningKey(metaclass=ABCMeta):
    """
    SigningKey instance
    """

    @abstractmethod
    def sign(self, data):
        """
        Sign data with private key

        Args:
            data:
        """

    @abstractmethod
    def get_verifying_key(self):
        """
        Get the associated verifying key

        Returns:
            A VerifyingKey object
        """

    @abstractmethod
    def to_ascii(self, prefix, encoding):
        """
        Encode the external value

        Args:
            prefix:
            encoding:
        """

    @staticmethod
    @abstractmethod
    def encode(private_value):
        """
        Encode the internal private_value to base58

        Args:
            private_value:
        """

    @staticmethod
    @abstractmethod
    def decode(private_base58):
        """
        Decode the base58 private value to internal value

        Args:
            private_base58 (base58):
        """
        raise NotImplementedError


class VerifyingKey(metaclass=ABCMeta):

    @abstractmethod
    def verify(self, data, signature):
        """
        Check the if the signature matches the data and this verifyingkey

        Args:
            data:
            signature:

        Returns:
            boolean:
        """

    @abstractmethod
    def to_ascii(self, prefix, encoding):
        """
        Encode the external value

        Args:
            prefix:
            encoding:
        """

    @staticmethod
    @abstractmethod
    def encode(public_value):
        """
        Encode the public key to base58 represented by the internal values

        Args:
            public_value
        """

    @staticmethod
    @abstractmethod
    def decode(public_base58):
        """
        Decode the base58 public_value to internal value

        Args:
            public_base58 (base58):
        """


class Ed25519SigningKey(ed25519.SigningKey, SigningKey):
    """
    PrivateKey instance
    """

    def __init__(self, key):
        """
        Instantiate the private key with the private_value encoded in base58

        Args:
            key (base58): base58 encoded private key
        """
        private_base64 = self.decode(key)
        super().__init__(private_base64, encoding='base64')

    def get_verifying_key(self):
        """
        Get the corresponding VerifyingKey

        Returns:
            VerifyingKey
        """
        vk = super().get_verifying_key()
        return Ed25519VerifyingKey(base58.b58encode(vk.to_bytes()))

    def to_ascii(self, prefix="", encoding='base58'):
        """
        convert external value to ascii with specified encoding

        Args:
            prefix (str):
            encoding (str): {'base58'|'base64'|'base32'|'base16'|'hex'}

        Returns:
            bytes: encoded string
        """
        if encoding == 'base58':
            return base58.b58encode(self.to_seed()).encode('ascii').decode('ascii').rstrip("=").encode('ascii')
        else:
            return super().to_ascii(prefix=prefix, encoding=encoding)

    def sign(self, data, prefix="", encoding="base58"):
        """
        Sign data with private key

        Args:
            data (str, bytes): data to sign
            prefix:
            encoding (str): base64, hex
        """
        if not isinstance(data, bytes):
            data = data.encode('ascii')
        if encoding == 'base58':
            signature = super().sign(data, prefix="", encoding='base64')
            return base58.b58encode(base64.b64decode(base64_add_padding(signature)))
        else:
            return super().sign(data, prefix="", encoding=encoding)

    @staticmethod
    def encode(private_base64):
        """
        Encode the base64 number private_base64 to base58

        Args:
            private_base64:
        """
        return base58.b58encode(base64.b64decode(private_base64)).encode('ascii')

    @staticmethod
    def decode(key):
        """
        Decode the base58 private_value to base64

        Args:
            key:
        """
        return base64.b64encode(base58.b58decode(key))


class Ed25519VerifyingKey(ed25519.VerifyingKey, VerifyingKey):

    def __init__(self, key):
        """
        Instantiate the public key with the compressed public value encoded in base58
        """
        public_base64 = self.decode(key)
        super().__init__(public_base64, encoding='base64')

    def verify(self, data, signature, prefix="", encoding='base58'):
        """
        Verify if the signature signs the data with this verifying key

        Args:
             data (bytes|str): data to be signed
             signature (bytes|str): {base64|base32|base16|hex|bytes} signature to be verified
             prefix: see super
             encoding: {base64|base32|base16|hex|bytes} encoding of the signature
        """
        try:
            if not isinstance(data, bytes):
                data = data.encode('ascii')
            if encoding == 'base58':
                super().verify(base58.b58decode(signature), data, prefix=prefix)
            else:
                super().verify(signature, data, prefix=prefix, encoding=encoding)
        except ed25519.BadSignatureError:
            return False

        return True

    def to_ascii(self, prefix="", encoding='base58'):
        """
        convert external value to ascii with specified encoding

        Args:
            prefix (str):
            encoding (str): {'base58'|'base64'|'base32'|'base16'|'hex'}

        Returns:
            bytes: encoded string
        """
        if encoding == 'base58':
            return base58.b58encode(self.vk_s).encode('ascii').decode('ascii').rstrip("=").encode()
        else:
            return super().to_ascii(prefix=prefix, encoding=encoding)

    @staticmethod
    def encode(public_base64):
        """
        Encode the public key represented by base64 to base58

        Args:
            public_base64
        """
        return Ed25519SigningKey.encode(public_base64)

    @staticmethod
    def decode(public_base58):
        """
        Decode the base58 public_value to base64

        Args:
            public_base58
        """
        return Ed25519SigningKey.decode(public_base58)


def ed25519_generate_key_pair():
    """
    Generate a new key pair and return the pair encoded in base58
    """
    sk, vk = ed25519.create_keypair()
    # Private key
    private_value_base58 = Ed25519SigningKey(base58.b58encode(sk.to_bytes())).to_ascii()

    # Public key
    public_value_compressed_base58 = Ed25519VerifyingKey(base58.b58encode(vk.to_bytes())).to_ascii()

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
