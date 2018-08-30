import math
from base64 import urlsafe_b64decode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from cryptoconditions.crypto import base64_add_padding
from cryptoconditions.exceptions import MissingDataError, ValidationError
from cryptoconditions.types.base_sha256 import BaseSha256
from cryptoconditions.schemas.fingerprint import RsaFingerprintContents

PUBLIC_EXPONENT = 65537
SALT_LENGTH = 32


class RsaSha256(BaseSha256):
    """RSA-SHA-256: RSA signature condition using SHA-256.

    This RSA condition uses RSA-PSS padding with SHA-256. The salt
    length is set equal the digest length of 32 bytes.

    The public exponent is fixed at 65537 and the public modulus must
    be between 128 (1017 bits) and 512 bytes (4096 bits) long.

    RSA-SHA-256 is assigned the type ID 3. It relies on the SHA-256 and
    RSA-PSS feature suites which corresponds to a feature bitmask of
    0x11.

    """
    TYPE_ID = 3
    TYPE_NAME = 'rsa-sha-256'
    TYPE_ASN1 = 'rsaSha256'
    TYPE_ASN1_CONDITION = 'rsaSha256Condition'
    TYPE_ASN1_FULFILLMENT = 'rsaSha256Fulfillment'
    TYPE_CATEGORY = 'simple'

    COST_RIGHT_SHIFT = 6    # 2**6 = 64

    def __init__(self):
        self.modulus = None
        self.signature = None

    def parse_json(self, json):
        self.modulus = urlsafe_b64decode(base64_add_padding(json['modulus']))
        self.signature = urlsafe_b64decode(
            base64_add_padding(json['signature']))

    def parse_asn1_dict_payload(self, data):
        self.modulus = data['modulus']
        self.signature = data['signature']

    @property
    def fingerprint_contents(self):
        """Produce the contents of the condition hash.

        This function is called internally by the `getCondition` method.

        Returns:
            bytes: Encoded contents of fingerprint hash.

        """
        if self.modulus is None:
            raise MissingDataError('Requires modulus')

        asn1_obj = nat_decode({'modulus': self.modulus},
                              asn1Spec=RsaFingerprintContents())
        asn1_der = der_encode(asn1_obj)
        return asn1_der

    @property
    def asn1_dict_payload(self):
        return {'modulus': self.modulus, 'signature': self.signature}

    def _set_public_modulus(self, modulus):
        """Set the public modulus.

        This is the modulus of the RSA public key. It has to be provided
        as raw bytes with no leading zeros.

        Args:
            modulus (bytes): Public RSA modulus.

        """
        if not isinstance(modulus, bytes):
            raise TypeError('Modulus must be bytes, was: {}'.format(modulus))

        if modulus[0] == 0:
            raise Exception('Modulus may not contain leading zeros')

        if not 128 <= len(modulus) <= 512:
            raise Exception(
                'Modulus must be between 128 bytes (1017 bits) and ' +
                '512 bytes (4096 bits), was: {} bytes'.format(len(modulus)))

        self.modulus = modulus

    def _set_signature(self, signature):
        """Set the signature manually.

        The signature must be a valid RSA-PSS siganture.

        Args:
            signature (bytes): RSA signature.

        """
        if not isinstance(signature, bytes):
            raise TypeError('Signature must be bytes, was: ' + signature)

        self.signature = signature

    def sign(self, message, private_key):
        """Sign the message.

        This method will take the provided message and create a
        signature using the provided RSA private key. The resulting
        signature is stored in the fulfillment.

        The key should be provided as a PEM encoded private key string.

        The message is padded using RSA-PSS with SHA256.

        Args:
            message (bytes): Message to sign.
            private_key (bytes):  RSA private key.

        """
        private_key_obj = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend(),
        )

        if self.modulus is None:
            m_int = private_key_obj.public_key().public_numbers().n
            m_bytes = m_int.to_bytes(
                (m_int.bit_length() + 7) // 8, 'big')
            self._set_public_modulus(m_bytes)

        self.signature = private_key_obj.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=SALT_LENGTH,
            ),
            hashes.SHA256(),
        )

    def calculate_cost(self):
        """Calculate the cost of fulfilling self condition.

        The cost of the RSA condition is the size of the modulus
        squared, divided By 64.

        Returns:
            int: Expected maximum cost to fulfill self condition.

        """
        if self.modulus is None:
            raise MissingDataError('Requires a public modulus')

        public_numbers = RSAPublicNumbers(
            PUBLIC_EXPONENT,
            int.from_bytes(self.modulus, byteorder='big'),
        )
        public_key = public_numbers.public_key(default_backend())
        modulus_bit_length = public_key.key_size
        # TODO watch out >> in Python is not the sane as JS >>>, may need to be
        # corrected. For instance see:
        # http://grokbase.com/t/python/python-list/0454t3tgaw/zero-fill-shift
        return int(math.pow(modulus_bit_length, 2)) >> RsaSha256.COST_RIGHT_SHIFT

    def validate(self, message):
        """Verify the signature of self RSA fulfillment.

        The signature of self RSA fulfillment is verified against the
        provided message and the condition's public modulus.

        Args:
            message (bytes): Message to verify.

        Returns:
            bool: Whether self fulfillment is valid.

        """
        if not isinstance(message, bytes):
            raise Exception(
                'Message must be provided as bytes, was: ' + message)

        public_numbers = RSAPublicNumbers(
            PUBLIC_EXPONENT,
            int.from_bytes(self.modulus, byteorder='big'),
        )
        public_key = public_numbers.public_key(default_backend())
        try:
            public_key.verify(
                        self.signature,
                        message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=SALT_LENGTH,
                        ),
                        hashes.SHA256()
                    )
        except InvalidSignature as exc:
            raise ValidationError('Invalid RSA signature') from exc

        return True
