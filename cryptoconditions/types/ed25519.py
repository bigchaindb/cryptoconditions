import json

import base58

from cryptoconditions.crypto import Ed25519VerifyingKey as VerifyingKey
from cryptoconditions.fulfillment import Fulfillment


class Ed25519Fulfillment(Fulfillment):

    TYPE_ID = 4
    FEATURE_BITMASK = 0x20
    PUBKEY_LENGTH = 32
    SIGNATURE_LENGTH = 64
    FULFILLMENT_LENGTH = PUBKEY_LENGTH + SIGNATURE_LENGTH

    def __init__(self, public_key=None):
        """
        ED25519: Ed25519 signature condition.

        This condition implements Ed25519 signatures.

        ED25519 is assigned the type ID 4. It relies only on the ED25519 feature suite
        which corresponds to a bitmask of 0x20.

        Args:
            public_key (VerifyingKey): Ed25519 publicKey
        """
        if public_key and isinstance(public_key, (str, bytes)):
            public_key = VerifyingKey(public_key)
        if public_key and not isinstance(public_key, VerifyingKey):
            raise TypeError
        self.public_key = public_key
        self.signature = None

    def write_common_header(self, writer):
        """
        Write static header fields.

        Some fields are common between the hash and the fulfillment payload. This
        method writes those field to anything implementing the Writer interface.
        It is used internally when generating the hash of the condition, when
        generating the fulfillment payload and when calculating the maximum fulfillment size.

        Args:
            writer (Writer, Hasher, Predictor): Target for outputting the header.
        """
        writer.write_var_octet_string(self.public_key)

    def sign(self, message, private_key):
        """
        Sign the message.

        This method will take the currently configured values for the message
        prefix and suffix and create a signature using the provided Ed25519 private key.

        Args:
            message (string): message to be signed
            private_key (string) Ed25519 private key
        """
        sk = private_key
        vk = VerifyingKey(base58.b58encode(sk.get_verifying_key().to_bytes()))

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

    def parse_payload(self, reader, *args):
        """
        Parse the payload of an Ed25519 fulfillment.

        Read a fulfillment payload from a Reader and populate this object with that fulfillment.

        Args:
            reader (Reader): Source to read the fulfillment payload from.
        """
        self.public_key = VerifyingKey(base58.b58encode(reader.read_octet_string(Ed25519Fulfillment.PUBKEY_LENGTH)))
        self.signature = reader.read_octet_string(Ed25519Fulfillment.SIGNATURE_LENGTH)

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
        writer.write_octet_string(self.public_key.to_bytes(), Ed25519Fulfillment.PUBKEY_LENGTH)
        writer.write_octet_string(self.signature, Ed25519Fulfillment.SIGNATURE_LENGTH)
        return writer

    def calculate_max_fulfillment_length(self):
        return Ed25519Fulfillment.FULFILLMENT_LENGTH

    def serialize_json(self):
        """
        Generate a JSON object of the fulfillment

        Returns:
        """
        return json.dumps(
            {
                'type': 'fulfillment',
                'type_id': Ed25519Fulfillment.TYPE_ID,
                'bitmask': self.bitmask,
                'public_key': self.public_key.to_ascii(encoding='base58').decode(),
                'signature': base58.b58encode(self.signature) if self.signature else None
            }
        )

    def parse_json(self, json_data):
        """
        Generate fulfillment payload from a json

        Args:
            json_data: json description of the fulfillment

        Returns:
            Fulfillment
        """
        self.public_key = VerifyingKey(json_data['public_key'])
        self.signature = base58.b58decode(json_data['signature']) if json_data['signature'] else None

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
