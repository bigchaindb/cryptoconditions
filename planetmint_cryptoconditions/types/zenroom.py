import string
import base58
from base64 import urlsafe_b64decode, urlsafe_b64encode
from multiprocessing import Manager, Process
from zenroom import zencode_exec
import json
from ast import literal_eval
from json.decoder import JSONDecodeError
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from planetmint_cryptoconditions.crypto import base64_add_padding, base64_remove_padding
from planetmint_cryptoconditions.types.base_sha256 import BaseSha256
from planetmint_cryptoconditions.schemas.fingerprint import ZenroomFingerprintContents

# from planetmint_cryptoconditions.zencode import read_zencode
# from zenroom_minimal import Zenroom


class ZenroomException(Exception):
    pass


class MalformedMessageException(Exception):
    def __init__(self, *args, **kwargs):
        return super().__init__("The message has to include the" " result of the zenroom execution", *args, **kwargs)


class ZenroomSha256(BaseSha256):

    TYPE_ID = 5
    TYPE_NAME = "zenroom-sha-256"
    TYPE_ASN1 = "zenroomSha256"
    TYPE_ASN1_CONDITION = "zenroomSha256Condition"
    TYPE_ASN1_FULFILLMENT = "zenroomSha256Fulfillment"
    TYPE_CATEGORY = "simple"

    CONSTANT_COST = 131072
    PUBLIC_KEY_LENGTH = 32
    SIGNATURE_LENGTH = 64

    # TODO docstrings
    def __init__(self, *, script=None, data=None, keys=None):
        """
        ZENROOM: Zenroom signature condition.

        This condition implements Zenroom signatures.

        ZENROOM is assigned the type ID 5.

        Args:
            script (str): Zenroom script (fulfillment)
                          This script will be used inside the verification, it takes as
                          input data from: the asset, the output and the metadata
            keys (dictionary): Public identities
            data (dictionary): data fixed in the output of the transaction

        """
        self._script = script
        self._keys = keys
        self._data = data
        if keys is not None:
            self._keys = self._validate_keys(keys)
        if data is not None:
            self._data = self._validate_data(data)
        if script is not None:
            self._script = self._validate_script(str(script))

    def _validate_script(self, script):
        # Any string could be a script, the only way to verify if it is valid
        # is to execute it, but I cannot because I don't have the data in the
        # asset and in the metadata
        if not isinstance(script, str):
            raise TypeError("the script must be a string")
        return script

    @property
    def script(self):
        return self._script

    @script.setter
    def script(self, script):
        if script is not None:
            self._script = self._validate_script(str(script))

    # All string must be ascii
    def _validate_keys(self, keys):
        if isinstance(keys, bytes):
            keys = json.loads(keys.decode())
        if not isinstance(keys, dict):
            raise TypeError("the keys must be a dictionary")
        dict_keys = keys.keys()
        if "asset" in dict_keys or "metadata" in dict_keys:
            raise TypeError("keys cannot have a asset or a metadata key")
        return keys

    @property
    def keys(self):
        return self._keys or b""

    @keys.setter
    def keys(self, keys):
        if keys is not None:
            self._keys = self._validate_keys(keys)

    def _validate_data(self, data):
        # Any dictionary (that can be serialized in json) could be valid data
        if not isinstance(data, dict):
            raise TypeError("the keys must be a dictionary")
        dict_keys = data.keys()
        if "asset" in dict_keys or "metadata" in dict_keys:
            raise TypeError("keys cannot have a asset or a metadata key")
        # If data is not serializable this will throw an exception
        json.dumps(data)
        return data

    @property
    def data(self):
        return self._data or b""

    @data.setter
    def data(self, data):
        if data is not None:
            self._data = self._validate_data(data)

    @property
    def json_keys(self):
        return json.dumps(
            self._keys,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @property
    def asn1_dict_payload(self):
        return {
            "script": self._script,
            "data": json.dumps(self._data),
            "keys": json.dumps(self._keys),
        }

    @property
    def fingerprint_contents(self):
        asn1_fingerprint_obj = nat_decode(
            {
                "script": self._script,
                "data": json.dumps(self._data),
                "keys": json.dumps(self._keys),
            },
            asn1Spec=ZenroomFingerprintContents(),
        )
        return der_encode(asn1_fingerprint_obj)

    def calculate_cost(self):
        # TODO needs to be modified ???
        return ZenroomSha256.CONSTANT_COST

    def to_asn1_dict(self):
        return {self.TYPE_ASN1: self.asn1_dict_payload}

    def convert_input_message_2_data(self, message):
        try:
            message["input"]
        except KeyError:
            message["input"] = {}
        try:
            message["output"]
        except KeyError:
            message["output"] = {}

        input_data = {} if self._data is None else self._data
        input_data = {**input_data, **message["input"]}
        output_data = message["output"]
        return input_data, output_data

    # TODO Adapt according to outcomes of
    # https://github.com/rfcs/crypto-conditions/issues/16
    def to_dict(self):
        """
        Generate a dict of the fulfillment

        Returns:
            dict: representing the fulfillment
        """
        return {
            "type": ZenroomSha256.TYPE_NAME,
            "script": base58.b58encode(json.dumps(self._script)),
            "data": base58.b58encode(json.dumps(self._data)),
            "keys": base58.b58encode(json.dumps(self._keys)),
        }

    # This function is not always necessary, sometime the initial message (transaction)
    # is not ready to be validated, we need a zenroom script which produces some
    # intermediate data that will be verified by the validate method

    # A common example is a signature (the name comes from this), with the private key
    # we produce the signature (we can do this in zenroom) and the we will verify it

    # Anyway we cannot fix the condition script in the code, because ECDH is not the
    # only time we need this (e.g. we could produce a bitcoin signed transaction and
    # the code would be different)
    def sign(self, message, condition_script, private_keys):
        try:
            message = json.loads(message)
        except JSONDecodeError:
            return False

        in_data, out_data = self.convert_input_message_2_data(message)
        result = zencode_exec(
            condition_script,
            keys=json.dumps(private_keys),
            data=json.dumps(in_data),
        )

        output = result.output if len(result.output) > 0 else "{}"
        output = json.loads(output)
        response = {"output": {**output, "logs": result.logs}}
        message = {**message, **response}
        return json.dumps(message)

    # TODO Adapt according to outcomes of
    # https://github.com/rfcs/crypto-conditions/issues/16
    def to_json(self):
        """
        Generate a dict of the fulfillment

        Returns:
            dict: representing the fulfillment
        """
        return {
            "type": ZenroomSha256.TYPE_NAME,
            "script": base64_remove_padding(urlsafe_b64encode(self._script)),
            "data": base64_remove_padding(urlsafe_b64encode(self._data)),
            "keys": base64_remove_padding(urlsafe_b64encode(self._keys)),
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
        if data.get("script"):
            self._script = base58.b58decode(data["script"])
        if data.get("data"):
            self._data = base58.b58decode(data["data"])
        if data.get("keys"):
            self._keys = base58.b58decode(data["keys"])

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
        self._script = urlsafe_b64decode(base64_add_padding(data["script"]))
        self._data = urlsafe_b64decode(base64_add_padding(data["data"]))
        self._keys = urlsafe_b64decode(base64_add_padding(data["keys"]))

    def parse_asn1_dict_payload(self, data):
        self._script = data["script"].decode()
        tmp_data = data["data"].decode("utf8") if data["data"].decode("utf8") != "null" else "None"
        self._data = literal_eval(tmp_data)
        tmp_keys = data["keys"].decode("utf8") if data["keys"].decode("utf8") != "null" else "None"
        self._keys = literal_eval(tmp_keys)

    def validate(self, *, message):
        """
        Verify the signature of this Zenroom fulfillment.

        The signature of this Zenroom fulfillment is verified against
        the provided message and script.

        Args:
            message (str): Message to validate against.

        Return:
            boolean: Whether this fulfillment is valid.
        """
        try:
            message = json.loads(message)
        except JSONDecodeError:
            return False
        except ValueError:
            raise MalformedMessageException()

        in_data, out_data = self.convert_input_message_2_data(message)

        # We can put pulic keys either in the keys or the data of zenroom
        result = zencode_exec(self.script, keys=json.dumps(self._keys), data=json.dumps(in_data))
        if len(result.output) == 0 and len(result.logs) > 0:
            return False

        try:
            result = json.loads(result.output)
            # output tag is only defined if zenroom returns a type (int, string, ...)
            # in case a 'variable' is returned, the output will look like follows: 'variable':'value'
            # that's the cause for the KeyError catch
            try:
                result["output"]
            except KeyError:
                return result == message["output"]
            else:
                return result["output"] == message["output"]
        except JSONDecodeError:
            return False
