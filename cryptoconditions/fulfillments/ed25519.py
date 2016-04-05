import base58

from cryptoconditions.ed25519 import Ed25519VerifyingKey
from cryptoconditions.fulfillment import Fulfillment


class Ed25519Fulfillment(Fulfillment):
    TYPE_ID = 4
    FEATURE_BITMASK = 0x20
    PUBKEY_LENGTH = 32
    SIGNATURE_LENGTH = 64
    FULFILLMENT_LENGTH = \
        1 + PUBKEY_LENGTH + \
        1 + SIGNATURE_LENGTH

    def __init__(self, public_key=None):
        """

        Args:
            public_key (Ed25519VerifyingKey): Ed25519 publicKey
        """
        if public_key and not isinstance(public_key, Ed25519VerifyingKey):
            raise TypeError
        self.public_key = public_key
        self.signature = None

    def sign(self, message, private_key):
        """
        Sign the message.

        This method will take the currently configured values for the message
        prefix and suffix and create a signature using the provided Ed25519 private key.

        Args:
            private_key (string) Ed25519 private key
        """
        sk = private_key
        vk = Ed25519VerifyingKey(base58.b58encode(sk.get_verifying_key().to_bytes()))

        self.public_key = vk

        # This would be the Ed25519ph version (JavaScript ES7):
        # const message = crypto.createHash('sha512')
        #   .update(Buffer.concat([this.messagePrefix, this.message]))
        #   .digest()

        self.signature = sk.sign(message, encoding=None)

    def generate_hash(self):
        """
        Generate the condition hash.

        Since the public key is the same size as the hash we'd be putting out here,
        we just return the public key.
        """
        if not self.public_key:
            raise ValueError('Requires a public publicKey')
        return self.public_key.to_bytes()

    def parse_payload(self, reader):
        """
        Parse the payload of an Ed25519 fulfillment.

        Read a fulfillment payload from a Reader and populate this object with that fulfillment.

        Args:
            reader (Reader): Source to read the fulfillment payload from.
        """
        self.public_key = Ed25519VerifyingKey(base58.b58encode(reader.read_var_bytes()))
        self.signature = reader.read_var_bytes()

    def write_payload(self, writer):
        """
        Generate the fulfillment payload.

        This writes the fulfillment payload to a Writer.

        FULFILLMENT_PAYLOAD =
            VARBYTES PUBLIC_KEY
            VARBYTES SIGNATURE

        Args:
            writer (Writer): Subject for writing the fulfillment payload.
        """
        writer.write_var_bytes(bytearray(self.public_key.to_bytes()))
        writer.write_var_bytes(self.signature)
        return writer

    def calculate_max_fulfillment_length(self):
        return self.FULFILLMENT_LENGTH

    def validate(self, message=None):
        """
        Verify the signature of this Ed25519 fulfillment.

        The signature of this Ed25519 fulfillment is verified against the provided message and public key.

        Args:
            message (str): Message to validate against.

        Return:
            boolean: Whether this fulfillment is valid.
        """
        if not (message and self.signature):
            return False

        return self.public_key.verify(message, self.signature, encoding=None)
