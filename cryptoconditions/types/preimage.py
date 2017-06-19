from base64 import b64decode, urlsafe_b64decode

from cryptoconditions.crypto import base64_add_padding
from cryptoconditions.types.base_sha256 import BaseSha256
from cryptoconditions.exceptions import MissingDataError


class PreimageSha256(BaseSha256):
    """ """

    TYPE_ID = 0
    TYPE_NAME = 'preimage-sha-256'
    TYPE_ASN1 = 'preimageSha256'
    TYPE_ASN1_CONDITION = 'preimageSha256Condition'
    TYPE_ASN1_FULFILLMENT = 'preimageSha256Fulfillment'
    TYPE_CATEGORY = 'simple'

    def __init__(self, preimage=None):
        """
        PREIMAGE-SHA-256: Hashlock condition using SHA-256.

        This type of condition is also called a hashlock. By creating a hash
        of a difficult-to-guess 256-bit random or pseudo-random integer it
        is possible to create a condition which the creator can trivially
        fulfill by publishing the random value. However, for anyone else,
        the condition is cryptgraphically hard to fulfill, because they
        would have to find a preimage for the given condition hash.

        PREIMAGE-SHA-256 is assigned the type ID 0. It relies on the SHA-256
        and PREIMAGE feature suites which corresponds to a feature bitmask
        of 0x03.

        The preimage is the only input to a SHA256 hashlock condition.

        Note that the preimage should contain enough (pseudo-random) data in order
        to be difficult to guess. A sufficiently large secret seed and a
        cryptographically secure pseudo-random number generator (CSPRNG) can be
        used to avoid having to store each individual preimage.

        Args:
             preimage: Secret data that will be hashed to form the condition.
        """
        if preimage and (not isinstance(preimage, bytes)):
            raise TypeError('Preimage must be bytes, was: {}'.format(preimage))
        self.preimage = preimage

    def to_dict(self):
        """
        Generate a dict of the fulfillment

        Returns:
            dict: representing the fulfillment
        """
        return {
            'type': 'fulfillment',
            'type_id': self.TYPE_ID,
            'preimage': self.preimage.decode()
        }

    @property
    def asn1_dict_payload(self):
        return {'preimage': self.preimage}

    def to_asn1_dict(self):
        return {PreimageSha256.TYPE_ASN1: self.asn1_dict_payload}

    @property
    def fingerprint_contents(self):
        if self.preimage is None:
            raise MissingDataError(
                'Could not calculate hash, no preimage provided')
        return self.preimage

    def parse_json(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillmjson
        Returns:
            Fulfillment
        """
        self.preimage = urlsafe_b64decode(base64_add_padding(data['preimage']))

    # TODO remove
    def parse_dict(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data (dict): description of the fulfillment

        Returns:
            Fulfillment
        """
        self.preimage = b64decode(data['preimage'])

    def parse_asn1_dict_payload(self, data):
        self.preimage = data['preimage']

    def calculate_cost(self):
        if self.preimage is None:
            raise MissingDataError('Preimage must be specified')
        return len(self.preimage)

    def validate(self, *args, **kwargs):
        """
        Validate this fulfillment.

        For a SHA256 hashlock fulfillment, successful parsing implies that the
        fulfillment is valid, so this method is a no-op.

        Returns:
             boolean: Validation result
        """
        return True
