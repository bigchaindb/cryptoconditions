import base64
import base58
import re
from functools import total_ordering
from itertools import compress
from urllib.parse import parse_qs

from abc import ABCMeta

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.encoder import encode as nat_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from cryptoconditions import TypeRegistry
from cryptoconditions.crypto import base64_add_padding, base64_remove_padding
from cryptoconditions.exceptions import ParsingError, PrefixError

from cryptoconditions.schemas.condition import Condition as Asn1Condition

CONDITION_URI_SCHEME = 'ni'

# Regex for validating conditions
# This is a generic, future-proof version of the crypto-condition regular expression.
CONDITION_REGEX = r'^ni:\/\/\/sha-256;([a-zA-Z0-9_-]{0,86})\?(.+)$'

# This is a stricter version based on limitations of the current implementation.
# Specifically, we can't handle bitmasks greater than 32 bits.
CONDITION_REGEX_STRICT = CONDITION_REGEX

INTEGER_REGEX = r'^0|[1-9]\d*$'


@total_ordering
class Condition(metaclass=ABCMeta):
    """
    Crypto-condition.

    A primary design goal of crypto-conditions was to keep the size of conditions
    constant. Even a complex multi-signature can be represented by the same size
    condition as a simple hashlock.

    However, this means that a condition only carries the absolute minimum
    information required. It does not tell you anything about its structure.

    All that is included with a condition is the fingerprint (usually a hash of
    the parts of the fulfillment that are known up-front, e.g. public keys), the
    maximum fulfillment size, the set of features used and the condition type.

    This information is just enough that an implementation can tell with
    certainty whether it would be able to process the corresponding fulfillment.
    """

    SUPPORTED_SUBTYPES = {
        'preimage-sha-256',
        'prefix-sha-256',
        'threshold-sha-256',
        'rsa-sha-256',
        'ed25519-sha-256',
    }

    MAX_SAFE_SUBTYPES = len(SUPPORTED_SUBTYPES)

    MAX_COST = 2097152

    # Expose regular expressions
    REGEX = CONDITION_REGEX
    REGEX_STRICT = CONDITION_REGEX_STRICT

    # The type is a unique integer ID assigned to each type of condition.
    type_id = None

    _hash = None
    _cost = None
    _subtypes = None

    def __eq__(self, other):
        return self.serialize_binary() == other.serialize_binary()

    def __lt__(self, other):
        return self.serialize_binary() < other.serialize_binary()

    # TODO make into a class method instead as it fits the purpose of an
    # alternative way to instantiate the class
    @staticmethod
    def from_uri(serialized_condition):
        """
        Create a Condition object from a URI.

        This method will parse a condition URI and construct a corresponding Condition object.

        Args:
            serialized_condition (str): URI representing the condition

        Returns:
            Condition: Resulting object
        """
        # TODO consider removing.
        if isinstance(serialized_condition, Condition):
            return serialized_condition
        # TODO Use static typing instead (e.g.: with mypy).
        elif not isinstance(serialized_condition, str):
            raise TypeError('Serialized condition must be a string')

        pieces = serialized_condition.split(':')
        if pieces[0] != CONDITION_URI_SCHEME:
            raise PrefixError(
                'Serialized condition must start with "{}:"'.format(
                    CONDITION_URI_SCHEME
                )
            )

        regex_match = re.match(CONDITION_REGEX_STRICT, serialized_condition)
        if not regex_match:
            raise ParsingError('Invalid condition format')

        qs_dict = parse_qs(regex_match.group(2))

        try:
            fingerprint_type = qs_dict['fpt'][0]
        except (KeyError, IndexError):
            raise ParsingError(
                'Invalid condition format: "fpt" parameter or value missing.')

        condition_type = TypeRegistry.find_by_name(fingerprint_type)
        try:
            cost = qs_dict['cost'][0]
        except (KeyError, IndexError):
            raise ParsingError(
                'Invalid condition format: "cost" parameter or value missing.')

        if not re.match(INTEGER_REGEX, cost):
            raise ParsingError('No or invalid cost provided')

        fingerprint = regex_match.group(1)
        condition = Condition()
        condition.type_id = condition_type['type_id']
        condition._subtypes = set()
        if condition_type['class'].TYPE_CATEGORY == 'compound':
            condition._subtypes.update(qs_dict['subtypes'][0].split(','))
        condition.hash = base64.urlsafe_b64decode(
            base64_add_padding(fingerprint))
        condition.cost = int(cost)
        return condition

    # TODO make into a class method instead as it fits the purpose of an
    # alternative way to instantiate the class
    @staticmethod
    def from_binary(data):
        """
        Create a Condition object from a binary blob.

        This method will parse a stream of binary data and construct a
        corresponding Condition object.

        Args:
            data (bytes): Binary data representing the condition.
        Returns:
            Condition: Resulting object
        """
        asn1_condtion_obj, residue = der_decode(data, asn1Spec=Asn1Condition())
        asn1_condition_dict = nat_encode(asn1_condtion_obj)
        return Condition.from_asn1_dict(asn1_condition_dict)

    # TODO make into a class method instead as it fits the purpose of an
    # alternative way to instantiate the class
    @staticmethod
    def from_asn1_dict(asn1_dict):
        asn1_type, value = asn1_dict.popitem()
        registered_type = TypeRegistry.find_by_asn1_type(asn1_type)
        # Instantiate condition
        condition = Condition()
        condition.type_id = registered_type['type_id']
        condition.hash = value['fingerprint']
        condition.cost = value['cost']
        condition._subtypes = set()
        if registered_type['class'].TYPE_CATEGORY == 'compound':
            subtypes = {
                TypeRegistry.find_by_type_id(type_id)['name']
                for type_id in compress(
                    range(Condition.MAX_SAFE_SUBTYPES),
                    map(lambda bit: int(bit), value['subtypes'])
                )
            }
            condition._subtypes.update(subtypes)

        return condition

    @classmethod
    def from_json(cls, json):
        return cls.from_asn1_dict(json)

    # TODO update docstrings
    @property
    def hash(self):
        """
        Return the hash of the condition.

        A primary component of all conditions is the hash. It encodes the static
        properties of the condition. This method enables the conditions to be
        constant size, no matter how complex they actually are. The data used to
        generate the hash consists of all the static properties of the condition
        and is provided later as part of the fulfillment.

        Return:
            Hash of the condition
        """
        if not self._hash:
            raise ValueError
        return self._hash

    # TODO update docstrings
    @hash.setter
    def hash(self, value):
        """
        Validate and set the hash of this condition.

        Typically conditions are generated from fulfillments and the hash is
        calculated automatically. However, sometimes it may be necessary to
        construct a condition URI from a known hash. This method enables that case.

        Args:
            value (Buffer): Hash as binary.

        Raises:
            Exception If hash value is not 32 bytes (256 bits) long.
        """
        # TODO Use more precise Exception class
        if len(value) != 32:
            raise ValueError(
                'Hash is of invalid length {}, should be 32'.format(len(value))
            )
        self._hash = value

    # TODO update docstrings
    @property
    def cost(self):
        """
        Return the maximum fulfillment length.

        The maximum fulfillment length is the maximum allowed length for any
        fulfillment payload to fulfill this condition.

        The condition defines a maximum fulfillment length which all
        implementations will enforce. This allows implementations to verify that
        their local maximum fulfillment size is guaranteed to accomodate any
        possible fulfillment for this condition.

        Otherwise an attacker could craft a fulfillment which exceeds the maximum
        size of one implementation, but meets the maximum size of another, thereby
        violating the fundamental property that fulfillments are either valid
        everywhere or nowhere.

        Return:
             (int) Maximum length (in bytes) of any fulfillment payload that fulfills this condition..
        """
        if not isinstance(self._cost, int):
            raise ValueError
        return self._cost

    # TODO update docstrings
    @cost.setter
    def cost(self, value):
        """
        .. todo:: docstrings

        Args:
             value (int): Maximum fulfillment payload length in bytes.
        """
        self._cost = value

    @property
    def type_name(self):
        return TypeRegistry.find_by_type_id(self.type_id)['name']

    @property
    def subtypes(self):
        return self._subtypes

    @subtypes.setter
    def subtypes(self, value):
        self._subtypes = value

    # TODO update docstrings
    def serialize_uri(self):
        """
        Generate the URI form encoding of this condition.

        Turns the condition into a URI containing only URL-safe characters. This
        format is convenient for passing around conditions in URLs, JSON and other text-based formats.

        "cc:" BASE16(TYPE_ID) ":" BASE16(BITMASK) ":" BASE64URL(HASH) ":" BASE10(MAX_COST)

        Returns:
            string: Condition as a URI
        """
        condition_type = TypeRegistry.find_by_type_id(self.type_id)
        condition_class = TypeRegistry.find_by_type_id(self.type_id)['class']
        include_subtypes = condition_class.TYPE_CATEGORY == 'compound'
        uri = 'ni:///sha-256;{}?fpt={}&cost={}'.format(
            base64_remove_padding(
                base64.urlsafe_b64encode(self.hash)).decode(),
            condition_type['name'],
            self.cost,
        )
        if include_subtypes:
            uri += '&subtypes=' + ','.join(sorted(self.subtypes))
        return uri

    # TODO update docstrings
    def serialize_binary(self):
        """
        Serialize condition to a buffer.

        Encodes the condition as a string of bytes. This is used internally for
        encoding subconditions, but can also be used to passing around conditions
        in a binary protocol for instance.

        CONDITION =
            VARUINT TYPE_BITMASK
            VARBYTES HASH
            VARUINT MAX_COST

        Return:
            Serialized condition
        """
        asn1_dict = self.to_asn1_dict()
        asn1_condition = nat_decode(asn1_dict, asn1Spec=Asn1Condition())
        binary_condition = der_encode(asn1_condition)
        return binary_condition

    def to_dict(self):
        """Generate a dict of the condition

        Returns:
            dict: representing the condition

        """
        return {
            'type_id': self.type_id,
            'hash': base58.b58encode(self.hash),
            'cost': self.cost,
            'subtypes': self.subtypes,
        }

    def to_json(self):
        return self.to_asn1_dict()

    def to_asn1_dict(self):
        condition_type = TypeRegistry.find_by_type_id(self.type_id)
        condition_class = condition_type['class']
        payload = {'fingerprint': self.hash, 'cost': self.cost}
        if condition_class.TYPE_CATEGORY == 'compound':
            subtype_ids = [
                TypeRegistry.find_by_name(subtype)['type_id']
                for subtype in self.subtypes
            ]
            bits = ['0' for bit in range(5)]
            for subtype_id in subtype_ids:
                bits[subtype_id] = '1'
            bitstring = ''.join(bits).rstrip('0')
            payload['subtypes'] = bitstring
        return {condition_class.TYPE_ASN1: payload}

    # TODO ILP Clarification NEEDED
    # The asn1 json payload that ILP uses in the JS implementation differs from
    # the dictionary payload generated by pyasn1 -- hence the question:
    # Is there a standard JSON representation of a condition?
    def to_asn1_json(self):
        asn1_type, value = self.to_asn1_dict().popitem()
        condition_type = TypeRegistry.find_by_asn1_type(asn1_type)
        return {'type': condition_type['asn1_condition'], 'value': value}

    # TODO ILP Clarification NEEDED
    def validate(self):
        """
        Ensure the condition is valid according the local rules.

        Checks the condition against the local subtypes (supported
        condition types) and the local maximum fulfillment size.

        Returns:
            bool: Whether the condition is valid according to local rules.
        """
        # Get class for type ID, throws on error
        TypeRegistry.find_by_type_id(self.type_id)

        # Subtypes can have at most 32 bits with current implementation
        if len(self.subtypes) > Condition.MAX_SAFE_SUBTYPES:
            raise ValueError('Subtypes too large to be safely represented')

        # Assert all requested features are supported by this implementation
        if any(subtype not in Condition.SUPPORTED_SUBTYPES
               for subtype in self.subtypes):
            raise ValueError('Condition requested unsupported feature suites')

        # Assert the requested fulfillment size
        # is supported by this implementation
        if self.cost > Condition.MAX_COST:
            raise ValueError(
                'Condition requested too large of a max fulfillment size')

        return True
