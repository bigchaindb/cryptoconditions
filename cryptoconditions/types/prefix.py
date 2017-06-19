from base64 import urlsafe_b64decode
from itertools import chain

from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from cryptoconditions.condition import Condition
from cryptoconditions.crypto import base64_add_padding
from cryptoconditions.fulfillment import Fulfillment
from cryptoconditions.exceptions import MissingDataError
from cryptoconditions.types.base_sha256 import BaseSha256
from cryptoconditions.schemas.fingerprint import PrefixFingerprintContents

CONDITION = 'condition'
FULFILLMENT = 'fulfillment'


class PrefixSha256(BaseSha256):
    """ """
    TYPE_ID = 1
    TYPE_NAME = 'prefix-sha-256'
    TYPE_ASN1 = 'prefixSha256'
    TYPE_ASN1_CONDITION = 'prefixSha256Condition'
    TYPE_ASN1_FULFILLMENT = 'prefixSha256Fulfillment'
    TYPE_CATEGORY = 'compound'

    CONSTANT_BASE_COST = 16384
    CONSTANT_COST_DIVISOR = 256

    def __init__(self):
        """
        PREFIX-SHA-256: Prefix condition using SHA-256.

        A prefix condition will prepend a static prefix to the message
        before passing the prefixed message on to a single subcondition.

        You can use prefix conditions to effectively narrow the scope of
        a public key or set of public keys. Simply take the condition
        representing the public key and place it as a subcondition in a
        prefix condition. Now any message passed to the subcondition
        will be prepended with a prefix.

        Prefix conditions are especially useful in conjunction with
        threshold conditions. You could have a group of signers, each
        using a different prefix to sign a common message.

        PREFIX-SHA-256 is assigned the type ID 1. It relies on the
        SHA-256 and PREFIX feature suites which corresponds to a feature
        bitmask of 0x05.

        """
        self._prefix = b''
        self._subcondition = None
        self._max_message_length = 16384

    @property
    def subcondition(self):
        """The (unfulfilled) subcondition.

        Each prefix condition builds on an existing condition which is
        provided via this method.

        Args:
           subcondition {Condition| str}: Condition object or URI
                string representing the condition that will receive the
                prefixed message.

        """
        return self._subcondition

    @subcondition.setter
    def subcondition(self, subcondition):
        if isinstance(subcondition, str):
            subcondition = Condition.from_uri(subcondition)
        elif not isinstance(subcondition,  Condition):
            raise Exception(
                'Subconditions must be URIs or objects of type Condition')
        self._subcondition = subcondition

    def _set_subfulfillment(self, subfulfillment):
        """Set the (fulfilled) subcondition.

        When constructing a prefix fulfillment, this method allows you to
        pass in a fulfillment for the condition that will receive the
        prefixed message.

        Note that you only have to add either the subcondition or a
        subfulfillment, but not both.

        Args:
            subfulfillment {Fulfillment|str}:  Fulfillment object or URI
                string representing the fulfillment to use as the
                subcondition.

        """
        if isinstance(subfulfillment, str):
            subfulfillment = Fulfillment.from_uri(subfulfillment)
        elif not isinstance(subfulfillment, Fulfillment):
            raise Exception(
                'Subfulfillments must be URIs or objects of type Fulfillment')
        self._subcondition = subfulfillment

    @property
    def prefix(self):
        """Set the prefix.

        The prefix will be prepended to the message during validation
        before the message is passed on to the subcondition.

        Args:
            prefix (bytes): Prefix to apply to the message.

        """
        return self._prefix

    @prefix.setter
    def prefix(self, prefix):
        if not isinstance(prefix, bytes):
            raise TypeError(
                'Prefix must be bytes, was: {}'.format(type(prefix)))
        self._prefix = prefix

    @property
    def max_message_length(self):
        return self._max_message_length

    @max_message_length.setter
    def max_message_length(self, max_message_length):
        """The threshold.

        Determines the threshold that is used to consider this
        condition fulfilled. If the number of valid subfulfillments is
        greater or equal to this number, the threshold condition is
        considered to be fulfilled.

        Args:
            max_message_length (int): Threshold.

        """
        if not isinstance(max_message_length, int) or max_message_length < 0:
            raise TypeError(
                'Max message length must be an integer greater than or '
                'equal to zero, was: {}'.format(max_message_length)
            )

        self._max_message_length = max_message_length

    @property
    def subtypes(self):
        """Get types used in this condition.

         This is a type of condition that contains a subcondition. A
         complete set of subtypes must contain the set of types that must
         be supported in order to validate this fulfillment. Therefore,
         we need to join the type of this condition to the types used in
         the subcondition.

         Returns:
             :obj:`set` of :obj:`str`: Complete type names for this
                 fulfillment.

        Note:
            Never include our own type as a subtype. The reason is that
            we already know that the validating implementation knows how
            to interpret this type, otherwise it wouldn't be able to
            verify this fulfillment to begin with.

        """
        return {t for t in chain(self.subcondition.subtypes,
                                 (self.subcondition.type_name,))
                if t != self.TYPE_NAME}

    @property
    def fingerprint_contents(self):
        """Produce the contents of the condition hash.

        This function is called internally by the ``condition``
        method/property.

        Returns:
            bytes: Encoded contents of fingerprint hash.

        """
        if not self.subcondition:
            raise MissingDataError('Requires subcondition')

        try:
            subcondition_asn1_dict = self.subcondition.condition.to_asn1_dict()
        except AttributeError:
            subcondition_asn1_dict = self.subcondition.to_asn1_dict()

        return der_encode(nat_decode({
            'prefix': self.prefix,
            'maxMessageLength': self.max_message_length,
            'subcondition': subcondition_asn1_dict,
        }, asn1Spec=PrefixFingerprintContents()))

    @property
    def asn1_dict_payload(self):
        return {
            'prefix': self.prefix,
            'maxMessageLength': self.max_message_length,
            'subfulfillment': self.subcondition.to_asn1_dict(),
        }

    def to_asn1_dict(self):
        return {self.TYPE_ASN1: self.asn1_dict_payload}

    def parse_json(self, data):
        self.prefix = urlsafe_b64decode(base64_add_padding(data['prefix']))
        self.max_message_length = data['maxMessageLength']
        self._set_subfulfillment(Fulfillment.from_json(data['subfulfillment']))

    def parse_asn1_dict_payload(self, data):
        self.prefix = data['prefix']
        self.max_message_length = data['maxMessageLength']
        self._set_subfulfillment(
            Fulfillment.from_asn1_dict(data['subfulfillment']))

    def calculate_cost(self):
        """Calculate the cost of fulfilling this condition.

        The cost of the prefix condition equals

            (1 + l/256) * (16384 + s)

        where l is the prefix length in bytes and s is the subcondition
        cost.

        Returns:
            int: Expected maximum cost to fulfill this condition

        """
        if self.prefix is None:
            raise MissingDataError('Prefix must be specified')

        if not self.subcondition:
            raise MissingDataError('Subcondition must be specified')

        try:
            subcondition_cost = self.subcondition.cost
        except AttributeError:
            subcondition_cost = self.subcondition.condition.cost

        cost = (len(self.prefix) +
                self.max_message_length + subcondition_cost + 1024)
        return cost

    def validate(self, message):
        """Check whether this fulfillment meets all validation criteria.

        This will validate the subfulfillment. The message will be
        prepended with the prefix before being passed to the
        subfulfillment's validation routine.

        Args:
            message (bytes): Message to validate against.

        Returns:
            bool: Whether this fulfillment is valid.

        """
        if not isinstance(self.subcondition, Fulfillment):
            raise Exception('Subcondition is not a fulfillment')

        if not isinstance(message, bytes):
            raise Exception(
                'Message must be provided as a bytes, was: '.format(message))

        return self.subcondition.validate(message=self.prefix + message)
