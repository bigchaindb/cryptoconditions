import base64
import re
from abc import ABCMeta, abstractmethod
from cryptoconditions import TypeRegistry
from cryptoconditions.condition import Condition
from cryptoconditions.crypto import base64_remove_padding, base64_add_padding
from cryptoconditions.exceptions import ParsingError
from cryptoconditions.lib import Writer, Reader, Predictor

FULFILLMENT_REGEX = r'^cf:([1-9a-f][0-9a-f]{0,3}|0):[a-zA-Z0-9_-]*$'


class Fulfillment(metaclass=ABCMeta):
    """
    From the specs (https://tools.ietf.org/html/draft-thomas-crypto-conditions-01):

        The term "fulfillment" refers to a description of a signed message
        and a signed message that matches the description.

        The description can be hashed and compared to a condition.  If the
        message matches the description and the hash of the description
        matches the condition, we say that the fulfillment fulfills the
        condition.

    """
    TYPE_ID = None
    REGEX = FULFILLMENT_REGEX
    FEATURE_BITMASK = None

    @staticmethod
    def from_uri(serialized_fulfillment):
        """
        Create a Fulfillment object from a URI.

        This method will parse a fulfillment URI and construct a corresponding Fulfillment object.

        Args:
            serialized_fulfillment (str): URI representing the fulfillment

        Return:
            Fulfillment: Resulting object
        """
        if isinstance(serialized_fulfillment, Fulfillment):
            return serialized_fulfillment
        elif not isinstance(serialized_fulfillment, str):
            raise TypeError('Serialized fulfillment must be a string')

        pieces = serialized_fulfillment.split(':')
        if not pieces[0] == 'cf':
            raise ValueError('Serialized fulfillment must start with "cf:"')

        if not re.match(Fulfillment.REGEX, serialized_fulfillment):
            raise ValueError('Invalid fulfillment format')
        # try:
        type_id = int(pieces[1], 16)
        payload = base64.urlsafe_b64decode(base64_add_padding(pieces[2]))

        cls = TypeRegistry.get_class_from_type_id(type_id)
        fulfillment = cls()

        fulfillment.parse_payload(Reader.from_source(payload), len(payload))
        # except Exception as e:
        #     raise ParsingError(str(e))

        return fulfillment

    @staticmethod
    def from_binary(reader):
        """
        Create a Fulfillment object from a binary blob.

        This method will parse a stream of binary data and construct a
        corresponding Fulfillment object.

        Args:
            reader (Reader): Binary stream implementing the Reader interface
        Returns:
            Fulfillment: Resulting object
        """
        reader = Reader.from_source(reader)

        cls_type = reader.read_uint16()
        cls = TypeRegistry.get_class_from_type_id(cls_type)

        fulfillment = cls()
        payload_length = reader.read_length_prefix()
        fulfillment.parse_payload(reader, payload_length)

        return fulfillment

    @staticmethod
    def from_dict(data):
        cls_type = data['type_id']
        cls = TypeRegistry.get_class_from_type_id(cls_type)

        fulfillment = cls()
        fulfillment.parse_dict(data)

        return fulfillment

    @property
    def type_id(self):
        """
        Return the type ID of this fulfillment.

        Returns:
            (int): Type ID as an integer.
        """
        return self.TYPE_ID

    @property
    def bitmask(self):
        """
        Return the bitmask of this fulfillment.

        For simple fulfillment types this is simply the bit representing this type.

        For meta-fulfillments, these are the bits representing the types of the subconditions.

        Returns:
            int: Bitmask corresponding to this fulfillment.
        """
        return self.FEATURE_BITMASK

    @property
    def condition(self):
        """
        Generate condition corresponding to this fulfillment.

        An important property of crypto-conditions is that the condition can always
        be derived from the fulfillment. This makes it very easy to post
        fulfillments to a system without having to specify which condition the
        relate to. The system can keep an index of conditions and look up any
        matching events related to that condition.

        Return:
            Condition: Condition corresponding to this fulfillment.
        """
        condition = Condition()
        condition.type_id = self.type_id
        condition.bitmask = self.bitmask
        condition.hash = self.generate_hash()
        condition.max_fulfillment_length = self.calculate_max_fulfillment_length()
        return condition

    @property
    def condition_uri(self):
        """
        Shorthand for getting condition URI.

        Returns:
            str: Condition URI.
        """
        return self.condition.serialize_uri()

    @property
    def condition_binary(self):
        """
        Shorthand for getting condition encoded as binary.

        Returns:
            bytes: Binary encoded condition.
        """
        return self.condition.serialize_binary()

    @abstractmethod
    def generate_hash(self):
        """
        Generate the hash of the fulfillment.

        This method is a stub and will be overridden by subclasses.

        Returns:
            bytes: Fingerprint of the condition.
        """

    def calculate_max_fulfillment_length(self):
        """
        Calculate the maximum length of the fulfillment payload.

        This implementation works by measuring the length of the fulfillment.
        Condition types that do not have a constant length will override this
        method with one that calculates the maximum possible length.

        Return:
            {Number} Maximum fulfillment length
        """
        predictor = Predictor()
        self.write_payload(predictor)
        return predictor.size

    def serialize_uri(self):
        """
        Generate the URI form encoding of this fulfillment.

        Turns the fulfillment into a URI containing only URL-safe characters. This
        format is convenient for passing around fulfillments in URLs, JSON and
        other text-based formats.

        "cf:" BASE16(TYPE_BIT) ":" BASE64URL(FULFILLMENT_PAYLOAD)

        Return:
             string: Fulfillment as a URI
        """
        return 'cf:{:x}:{}'.format(
            self.type_id,
            base64_remove_padding(base64.urlsafe_b64encode(self.serialize_payload())).decode('utf-8'))

    def serialize_binary(self):
        """
        Serialize fulfillment to a buffer.

        Encodes the fulfillment as a string of bytes. This is used internally for
        encoding subfulfillments, but can also be used to passing around
        fulfillments in a binary protocol for instance.

        FULFILLMENT =
            VARUINT TYPE_BIT
            FULFILLMENT_PAYLOAD

        Return:
            Serialized fulfillment
        """
        writer = Writer()
        writer.write_uint16(self.type_id)
        writer.write_var_octet_string(self.serialize_payload())
        return writer.buffer

    def serialize_payload(self):
        """
        Return the fulfillment payload as a buffer.

        Note that the fulfillment payload is not the standard format for passing
        fulfillments in binary protocols. Use `serializeBinary` for that. The
        fulfillment payload is purely the type-specific data and does not include the bitmask.

        Return:
            Buffer: Fulfillment payload
        """
        writer = Writer()
        self.write_payload(writer)
        return writer.buffer

    @abstractmethod
    def write_payload(self, writer):
        """
        Generate the fulfillment payload.

        Args:
            writer (Writer, Predictor): Subject for writing the fulfillment payload.
        """

    @abstractmethod
    def parse_payload(self, reader, *args):
        """
        Parse the payload of the fulfillment.

        Args:
            reader (Reader): Source to read the fulfillment payload from.
        """

    @abstractmethod
    def to_dict(self):
        """
        Generate a dict of the fulfillment

        Returns:
        """

    @abstractmethod
    def parse_dict(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data: dict description of the fulfillment

        Returns:
            Fulfillment
        """

    @abstractmethod
    def validate(self, *args, **kwargs):
        """
        Validate this fulfillment

        Returns:
            boolean: Validation result
        """
