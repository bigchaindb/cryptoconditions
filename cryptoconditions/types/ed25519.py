import base58
from base64 import urlsafe_b64decode, urlsafe_b64encode

from nacl.signing import VerifyKey, SigningKey
from nacl.exceptions import BadSignatureError
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from cryptoconditions.crypto import base64_add_padding, base64_remove_padding
from cryptoconditions.types.base_sha256 import BaseSha256
from cryptoconditions.schemas.fingerprint import Ed25519FingerprintContents


class Ed25519Sha256(BaseSha256):
    """ """

    TYPE_ID = 4
    TYPE_NAME = 'ed25519-sha-256'
    TYPE_ASN1 = 'ed25519Sha256'
    TYPE_ASN1_CONDITION = 'ed25519Sha256Condition'
    TYPE_ASN1_FULFILLMENT = 'ed25519Sha256Fulfillment'
    TYPE_CATEGORY = 'simple'

    CONSTANT_COST = 131072
    PUBLIC_KEY_LENGTH = 32
    SIGNATURE_LENGTH = 64

    # TODO docstrings
    def __init__(self, *, public_key=None, signature=None):
        """
        ED25519: Ed25519 signature condition.

        This condition implements Ed25519 signatures.

        ED25519 is assigned the type ID 4. It relies only on the ED25519 feature suite
        which corresponds to a bitmask of 0x20.

        Args:
            public_key (bytes): Ed25519 public key.
            signature (bytes): Signature.

        """
        if public_key is not None:
            self._validate_public_key(public_key)
        self._public_key = public_key
        if signature is not None:
            self._validate_signature(signature)
        self._signature = signature

    # TODO check type or use static typing (mypy)
    def _validate_public_key(self, public_key):
        if not isinstance(public_key, bytes):
            raise TypeError('public_key must be bytes')
        if len(public_key) != self.PUBLIC_KEY_LENGTH:
            raise ValueError(
                'Public key must be {} bytes, was: {}'.format(
                    self.PUBLIC_KEY_LENGTH, len(public_key)))
        # TODO More validation? Ask ILP folks.
        return public_key

    @property
    def public_key(self):
        return self._public_key

    @public_key.setter
    # TODO check type or use static typing (mypy)
    def public_key(self, public_key):
        self._public_key = self._validate_public_key(public_key)

    # TODO check type or use static typing (mypy)
    def _validate_signature(self, signature):
        if not isinstance(signature, bytes):
            raise TypeError('signature must be bytes')
        if len(signature) != self.SIGNATURE_LENGTH:
            raise Exception(
                'Signature must be {} bytes, was: {}'.format(
                    self.SIGNATURE_LENGTH, len(signature)))
        return signature

    @property
    def signature(self):
        return self._signature

    @signature.setter
    # TODO check type or use static typing (mypy)
    # def signature(self, signature: bytes) -> None:
    def signature(self, signature):
        self._signature = self._validate_signature(signature)

    @property
    def asn1_dict_payload(self):
        return {'publicKey': self.public_key, 'signature': self.signature}

    @property
    def fingerprint_contents(self):
        asn1_fingerprint_obj = nat_decode(
            {'publicKey': self.public_key},
            asn1Spec=Ed25519FingerprintContents(),
        )
        return der_encode(asn1_fingerprint_obj)

    # TODO check types or use static typing (mypy)
    def sign(self, message, private_key):
        """
        Sign the message.

        This method will take the currently configured values for the message
        prefix and suffix and create a signature using the provided Ed25519 private key.

        Args:
            message (bytes): message to be signed
            private_key (bytes) Ed25519 private key

        """
        sk = SigningKey(private_key)
        self.public_key = sk.verify_key.encode()
        self.signature = sk.sign(message).signature
        return self.signature

    def calculate_cost(self):
        return Ed25519Sha256.CONSTANT_COST

    def to_asn1_dict(self):
        return {self.TYPE_ASN1: self.asn1_dict_payload}

    # TODO Adapt according to outcomes of
    # https://github.com/rfcs/crypto-conditions/issues/16
    def to_dict(self):
        """
        Generate a dict of the fulfillment

        Returns:
            dict: representing the fulfillment
        """
        return {
            'type': Ed25519Sha256.TYPE_NAME,
            'public_key': base58.b58encode(self.public_key),
            'signature': base58.b58encode(self.signature) if self.signature else None
        }

    # TODO Adapt according to outcomes of
    # https://github.com/rfcs/crypto-conditions/issues/16
    def to_json(self):
        """
        Generate a dict of the fulfillment

        Returns:
            dict: representing the fulfillment
        """
        return {
            'type': Ed25519Sha256.TYPE_NAME,
            'public_key': base64_remove_padding(
                urlsafe_b64encode(self.public_key)),
            'signature': base64_remove_padding(
                urlsafe_b64encode(self.signature)) if self.signature else None
        }

    # TODO Adapt according to outcomes of
    # https://github.com/rfcs/crypto-conditions/issues/16
    def parse_dict(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillment

        Returns:
            Fulfillment
        """
        self.public_key = base58.b58decode(data['public_key'])
        if data['signature']:
            self.signature = base58.b58decode(data['signature'])

    # TODO Adapt according to outcomes of
    # https://github.com/rfcs/crypto-conditions/issues/16
    def parse_json(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillment

        Returns:
            Fulfillment
        """
        self.public_key = urlsafe_b64decode(base64_add_padding(
            data['publicKey']))
        self.signature = urlsafe_b64decode(base64_add_padding(
            data['signature']))

    def parse_asn1_dict_payload(self, data):
        self.public_key = data['publicKey']
        self.signature = data['signature']

    def validate(self, *, message):
        """
        Verify the signature of this Ed25519 fulfillment.

        The signature of this Ed25519 fulfillment is verified against
        the provided message and public key.

        Args:
            message (str): Message to validate against.

        Return:
            boolean: Whether this fulfillment is valid.
        """
        try:
            returned_message = VerifyKey(self.public_key).verify(
                message, signature=self.signature)
        except BadSignatureError:
            return False
        # TODO Check returned message against given message
        return True
