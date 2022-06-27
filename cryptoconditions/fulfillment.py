import base64
from abc import ABCMeta, abstractmethod

from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.native.decoder import decode as nat_decode
from pyasn1.codec.native.encoder import encode as nat_encode
from pyasn1.error import PyAsn1Error, SubstrateUnderrunError

from cryptoconditions import TypeRegistry
from cryptoconditions.condition import Condition
from cryptoconditions.crypto import base64_add_padding, base64_remove_padding
from cryptoconditions.exceptions import ASN1DecodeError, ASN1EncodeError
from cryptoconditions.schemas.fulfillment import Fulfillment as Asn1Fulfillment


class Fulfillment(metaclass=ABCMeta):
    """Base class for fulfillment types."""

    @staticmethod
    def from_uri(serialized_fulfillment):
        """
        Create a Fulfillment object from a URI.

        This method will parse a fulfillment URI and construct a
        corresponding Fulfillment object.

        Args:
            serialized_fulfillment (str): URI representing the fulfillment

        Return:
            Fulfillment: Resulting object
        """
        if not isinstance(serialized_fulfillment, str):
            raise TypeError('Serialized fulfillment must be a string')
        uri_bytes = base64.urlsafe_b64decode(
            base64_add_padding(serialized_fulfillment))
        return Fulfillment.from_binary(uri_bytes)

    @staticmethod
    def from_binary(data):
        """
        Create a Fulfillment object from a DER encoded binary
        representation of a fulfillment.

        Args:
            data (bytes): DER encoded fulfillment in bytes.
        Returns:
            Fulfillment: :class:`~.Fulfillment` instance.

        """
        try:
            asn1_obj, _ = der_decode(data, asn1Spec=Asn1Fulfillment())
        except (SubstrateUnderrunError, PyAsn1Error, TypeError) as exc:
            raise ASN1DecodeError('Failed to decode fulfillment.') from exc
        asn1_dict = nat_encode(asn1_obj)
        return Fulfillment.from_asn1_dict(asn1_dict)

    @staticmethod
    def from_asn1_dict(asn1_dict):
        asn1_type, value = asn1_dict.popitem()
        instance = TypeRegistry.find_by_asn1_type(asn1_type)['class']()
        instance.parse_asn1_dict_payload(value)
        instance.asn1_dict = {asn1_type: value}
        return instance

    @staticmethod
    def from_dict(data):
        type_ = TypeRegistry.find_by_name(data['type'])
        fulfillment = type_['class']()
        fulfillment.parse_dict(data)
        return fulfillment

    @staticmethod
    def from_json(data):
        type_ = TypeRegistry.find_by_name(data['type'])
        fulfillment = type_['class']()
        fulfillment.parse_json(data)
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
    def type_name(self):
        return self.TYPE_NAME

    @property
    def subtypes(self):
        return set()

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
        condition.hash = self.generate_hash()
        condition.cost = self.calculate_cost()
        condition.subtypes = self.subtypes
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

    @abstractmethod
    def calculate_cost(self):
        """Calculate the cost of the fulfillment payload.

        Each condition type has a standard deterministic formula for
        estimating the cost of validating the fulfillment. This is an
        abstract method which will be overridden by each of the types
        with the actual formula.

        Returns:
            int: The cost of the fulfillment payload.

        """

    def serialize_uri(self):
        """
        Generate the URI form encoding of this fulfillment.

        Turns the fulfillment into a URI containing only URL-safe
        characters. This format is convenient for passing around
        fulfillments in URLs, JSON and other text-based formats.

        Return:
             str: Fulfillment as a URI
        """
        return base64_remove_padding(
            base64.urlsafe_b64encode(self.serialize_binary())).decode()

    def serialize_binary(self):
        """
        Serialize fulfillment to bytes.

        Encodes the fulfillment as a string of bytes. This is used
        internally for encoding subfulfillments, but can also be used to
        passing around fulfillments in a binary protocol for instance.

        Returns:
            bytes: Serialized fulfillment (DER encoded).
        """
        asn1_dict = {self.TYPE_ASN1: self.asn1_dict_payload}
        try:
            asn1 = nat_decode(asn1_dict, asn1Spec=Asn1Fulfillment())
        except TypeError as exc:
            raise ASN1DecodeError(
                'Internal error! Failed to transform dict "{}" '
                'into pyasn1 schema object.'.format(asn1_dict)
            ) from exc
        try:
            bin_obj = der_encode(asn1)
        except PyAsn1Error as exc:
            raise ASN1EncodeError('Failed to encode fulfillment.') from exc
        return bin_obj

    def to_dict(self):
        """
        Generate a dict of the fulfillment

        Returns:
        """

    @property
    def asn1_dict(self):
        """Dictionary representation of asn1 object."""
        return self._asn1_dict

    @asn1_dict.setter
    def asn1_dict(self, value):
        self._asn1_dict = value

    def parse_dict(self, data):
        """
        Generate fulfillment payload from a dict

        Args:
            data: dict description of the fulfillment

        Returns:
            Fulfillment
        """

    @abstractmethod
    def parse_asn1_dict_payload(self, data):
        """
        .. todo:: write docs

        """

    @abstractmethod
    def validate(self, *args, **kwargs):
        """
        Validate this fulfillment

        Returns:
            boolean: Validation result
        """
