import json
import base58
import base64
import re

from abc import ABCMeta

from cryptoconditions import TypeRegistry
from cryptoconditions.crypto import base64_add_padding, base64_remove_padding
from cryptoconditions.lib import Writer, Reader


# Regex for validating conditions
# This is a generic, future-proof version of the crypto-condition regular expression.
CONDITION_REGEX = \
    r'^cc:([1-9a-f][0-9a-f]{0,3}|0):[1-9a-f][0-9a-f]{0,15}:[a-zA-Z0-9_-]{0,86}:([1-9][0-9]{0,17}|0)$'
# This is a stricter version based on limitations of the current implementation.
# Specifically, we can't handle bitmasks greater than 32 bits.
CONDITION_REGEX_STRICT = \
    r'^cc:([1-9a-f][0-9a-f]{0,3}|0):[1-9a-f][0-9a-f]{0,7}:[a-zA-Z0-9_-]{0,86}:([1-9][0-9]{0,17}|0)$'


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
    # Our current implementation can only represent up to 32 bits for our bitmask
    MAX_SAFE_BITMASK = 0xffffffff

    # Feature suites supported by this implementation
    SUPPORTED_BITMASK = 0x3f

    # Max fulfillment size supported by this implementation
    MAX_FULFILLMENT_LENGTH = 65535

    # Expose regular expressions
    REGEX = CONDITION_REGEX
    REGEX_STRICT = CONDITION_REGEX_STRICT

    # For simple condition types this is simply the bit representing this type.
    # For structural conditions, this is the bitwise OR of the bitmasks of
    # the condition and all its subconditions, recursively.
    bitmask = None

    # The type is a unique integer ID assigned to each type of condition.
    type_id = None

    _hash = None
    _max_fulfillment_length = None

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
        if isinstance(serialized_condition, Condition):
            return serialized_condition
        elif not isinstance(serialized_condition, str):
            raise TypeError('Serialized condition must be a string')

        pieces = serialized_condition.split(':')
        if not pieces[0] == 'cc':
            raise ValueError('Serialized condition must start with "cc:"')

        if not re.match(CONDITION_REGEX_STRICT, serialized_condition):
            raise ValueError('Invalid condition format')

        condition = Condition()
        condition.type_id = int(pieces[1], 16)
        condition.bitmask = int(pieces[2], 16)
        condition.hash = base64.urlsafe_b64decode(base64_add_padding(pieces[3]))
        condition.max_fulfillment_length = int(pieces[4])

        return condition

    @staticmethod
    def from_binary(reader):
        """
        Create a Condition object from a binary blob.

        This method will parse a stream of binary data and construct a
        corresponding Condition object.

        Args:
            reader (Reader): Binary stream implementing the Reader interface
        Returns:
            Condition: Resulting object
        """
        reader = Reader.from_source(reader)

        # Instantiate condition
        condition = Condition()
        condition.parse_binary(reader)

        return condition

    @staticmethod
    def from_json(json_data):
        """
        Create a Condition object from a json dict.

        Args:
            json_data (dict): Dictionary containing the condition payload

        Returns:
            Condition: Resulting object
        """
        condition = Condition()
        condition.parse_json(json_data)

        return condition

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

    @hash.setter
    def hash(self, value):
        """
        Validate and set the hash of this condition.

        Typically conditions are generated from fulfillments and the hash is
        calculated automatically. However, sometimes it may be necessary to
        construct a condition URI from a known hash. This method enables that case.

        Args:
            value (Buffer): Hash as binary.
        """
        self._hash = value

    @property
    def max_fulfillment_length(self):
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
        if not isinstance(self._max_fulfillment_length, int):
            raise ValueError
        return self._max_fulfillment_length

    @max_fulfillment_length.setter
    def max_fulfillment_length(self, value):
        """
        Set the maximum fulfillment length.

        The maximum fulfillment length is normally calculated automatically, when
        calling `Fulfillment#getCondition`. However, when

        Args:
             value (int): Maximum fulfillment payload length in bytes.
        """
        self._max_fulfillment_length = value

    def serialize_uri(self):
        """
        Generate the URI form encoding of this condition.

        Turns the condition into a URI containing only URL-safe characters. This
        format is convenient for passing around conditions in URLs, JSON and other text-based formats.

        "cc:" BASE16(TYPE_ID) ":" BASE16(BITMASK) ":" BASE64URL(HASH) ":" BASE10(MAX_FULFILLMENT_LENGTH)

        Returns:
            string: Condition as a URI
        """

        return 'cc:{:x}:{:x}:{}:{}'.format(
            self.type_id,
            self.bitmask,
            base64_remove_padding(base64.urlsafe_b64encode(self.hash)).decode('utf-8'),
            self.max_fulfillment_length
        )

    def serialize_binary(self):
        """
        Serialize condition to a buffer.

        Encodes the condition as a string of bytes. This is used internally for
        encoding subconditions, but can also be used to passing around conditions
        in a binary protocol for instance.

        CONDITION =
            VARUINT TYPE_BITMASK
            VARBYTES HASH
            VARUINT MAX_FULFILLMENT_LENGTH

        Return:
            Serialized condition
        """
        writer = Writer()
        writer.write_uint16(self.type_id)
        writer.write_var_uint(self.bitmask)
        writer.write_var_octet_string(self.hash)
        writer.write_var_uint(self.max_fulfillment_length)
        return writer.buffer

    def parse_binary(self, reader):
        """
        Parse any condition in binary format.

        Will populate the condition object with data from the provided binary
        stream.

        Args:
             reader (Reader): Binary stream containing the condition.
        """
        self.type_id = reader.read_uint16()
        self.bitmask = reader.read_var_uint()

        # TODO: Ensure bitmask is supported?
        self.hash = reader.read_var_octet_string()
        self.max_fulfillment_length = reader.read_var_uint()

    def serialize_json(self):
        return json.dumps(
            {
                'type': 'condition',
                'type_id': self.type_id,
                'bitmask': self.bitmask,
                'hash': base58.b58encode(self.hash),
                'max_fulfillment_length': self.max_fulfillment_length
            }
        )

    def parse_json(self, json_data):
        """

        Args:
            json_data (dict):
        Returns:
            Condition with payload
        """
        self.type_id = json_data['type_id']
        self.bitmask = json_data['bitmask']

        self.hash = base58.b58decode(json_data['hash'])
        self.max_fulfillment_length = json_data['max_fulfillment_length']

    def validate(self):
        """
        Ensure the condition is valid according the local rules.

        Checks the condition against the local bitmask (supported condition types)
        and the local maximum fulfillment size.

        Returns:
            bool: Whether the condition is valid according to local rules.
        """
        # Get class for type ID, throws on error
        TypeRegistry.get_class_from_type_id(self.type_id)

        # Bitmask can have at most 32 bits with current implementation
        if self.bitmask > Condition.MAX_SAFE_BITMASK:
            raise ValueError('Bitmask too large to be safely represented')

        # Assert all requested features are supported by this implementation
        if self.bitmask & ~Condition.SUPPORTED_BITMASK:
            raise ValueError('Condition requested unsupported feature suites')

        # Assert the requested fulfillment size is supported by this implementation
        if self.max_fulfillment_length > Condition.MAX_FULFILLMENT_LENGTH:
            raise ValueError('Condition requested too large of a max fulfillment size')

        return True
