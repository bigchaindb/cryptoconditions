import base58
from base64 import urlsafe_b64decode, urlsafe_b64encode
from multiprocessing import Manager, Process
from zenroom import zencode_exec
import json
from json.decoder import JSONDecodeError
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from cryptoconditions.crypto import base64_add_padding, base64_remove_padding
from cryptoconditions.types.base_sha256 import BaseSha256
from cryptoconditions.schemas.fingerprint import ZenroomFingerprintContents
from capturer import CaptureOutput
# from cryptoconditions.zencode import read_zencode
# from zenroom_minimal import Zenroom

def _execute(result, *args, **kwargs):
    z = zencode_exec(*args, **kwargs)
    result.put(z)

class ZenroomException(Exception):
    pass

class MalformedMessageException(Exception):
    def __init__(self, *args, **kwargs):
        return super().__init__(
            "The message has to include the"
            " result of the zenroom execution", *args, **kwargs)


class ZenroomSha256(BaseSha256):

    TYPE_ID = 5
    TYPE_NAME = 'zenroom-sha-256'
    TYPE_ASN1 = 'zenroomSha256'
    TYPE_ASN1_CONDITION = 'zenroomSha256Condition'
    TYPE_ASN1_FULFILLMENT = 'zenroomSha256Fulfillment'
    TYPE_CATEGORY = 'simple'

    CONSTANT_COST = 131072
    PUBLIC_KEY_LENGTH = 32
    SIGNATURE_LENGTH = 64

    # TODO docstrings
    def __init__(self, *, script, data, keys):
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
        self._script = self._validate_script(script)
        if keys is not None:
            self._validate_keys(keys)
        self._keys = keys
        if data is not None:
            self._validate_data(data)
        self._data = data

    def _validate_script(self, script):
        # Any string could be a script, the only way to verify if it is valid
        # is to execute it, but I cannot because I don't have the data in the
        # asset and in the metadata
        if not isinstance(script, str):
            raise TypeError('the script must be a string')
        return script

    @property
    def script(self):
        return self._script

    @script.setter
    def script(self, script):
        self._script = self._validate_script(script)

    # All string must be ascii
    def _validate_keys(self, keys):
        if not isinstance(keys, dict):
            raise TypeError('the keys must be a dictionary')
        for name in keys.keys():
            if not isinstance(name, str):
                raise TypeError('{} is not the name of a user', name)
            for k in keys[name].keys():
                if not isinstance(k, str):
                    raise TypeError('key type must be a string', name)
                if not isinstance(keys[name][k], str):
                    raise TypeError('the output of zencode keys must be a string', name)
        return keys

    @property
    def keys(self):
        return self._keys or b''

    @keys.setter
    def keys(self, keys):
        self._keys = self._validate_keys(keys)

    def _validate_data(self, data):
        # Any dictionary (that can be serialized in json) could be valid data
        if not isinstance(data, dict):
            raise TypeError('the keys must be a dictionary')
        # If data is not serializable this will throw an exception
        json.dumps(data)
        return data

    @property
    def data(self):
        return self._data or b''

    @data.setter
    def data(self, data):
        self._data = self._validate_data(data)

    @property
    def json_keys(self):
        return json.dumps(
            self.keys,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False,
        )

    @property
    def asn1_dict_payload(self):
        return {
            'script': self.script,
            'data': json.dumps(self.data),
            'keys': json.dumps(self.keys),
        }

    @property
    def fingerprint_contents(self):
        asn1_fingerprint_obj = nat_decode(
            {'script': self.script,
             'data': json.dumps(self.data),
             'keys': json.dumps(self.keys)},
            asn1Spec=ZenroomFingerprintContents(),
        )
        return der_encode(asn1_fingerprint_obj)

    def calculate_cost(self):
        # TODO needs to be modified ???
        return ZenroomSha256.CONSTANT_COST

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
            'type': ZenroomSha256.TYPE_NAME,
            'script': base58.b58encode(json.dumps(self.script)),
            'keys': base58.b58encode(json.dumps(self.keys)),
        }

    # Create a new process and run a zenroom instance in it
    @staticmethod
    def run_zenroom(script, keys=None, data=None):
        keys = keys or {}
        data = data or {}
        m = Manager()
        q = m.Queue()
        with CaptureOutput() as capturer:
            p = Process(target=_execute,
                        args=(q, script,),
                        kwargs={'keys': json.dumps(keys),
                                'data': json.dumps(data)})
            p.start()
            p.join()

        if q.empty():
            raise ZenroomException(capturer.get_text())
        result = q.get()

        return result

    # This function is not always necessary, sometime the initial message (transaction)
    # is not ready to be validated, we need a zenroom script which produces some
    # intermediate data that will be verified by the validate method

    # A common example is a signature (the name comes from this), with the private key
    # we produce the signature (we can do this in zenroom) and the we will verify it

    # Anyway we cannot fix the condition script in the code, because ECDH is not the
    # only time we need this (e.g. we could produce a bitcoin signed transaction and
    # the code would be different)
    def sign(self, message, condition_script, private_keys):
        message = json.loads(message)
        data = {}
        if 'data' in message['asset'].keys():
            data['asset'] = message['asset']['data']
        if self.data is not None:
            data['output'] = self.data

        result = ZenroomSha256.run_zenroom(condition_script,
                                           {"keys": private_keys},
                                           data)
        message['metadata'] = {'data': json.loads(result.output),
                               'result': 'ok'}

        print(message)
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
            'type': ZenroomSha256.TYPE_NAME,
            'script': base64_remove_padding(
                urlsafe_b64encode(self.script)),
            'keys': base64_remove_padding(
                urlsafe_b64encode(self.keys)),
            # 'conf': base64_remove_padding(
            #     urlsafe_b64encode(self.conf)),
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
        if data.get('script'):
            self.script = base58.b58decode(data['script'])
        if data.get('keys'):
            self.keys = base58.b58decode(data['keys'])

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
        self.script = urlsafe_b64decode(base64_add_padding(
            data['script']))
        self.keys = urlsafe_b64decode(base64_add_padding(
            data['keys']))

    def parse_asn1_dict_payload(self, data):
        self.script = data['script']
        self.keys = data['keys']

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
        data = {}
        try:
            if message['asset']['data']:
                data['asset'] = message['asset']['data']
        except JSONDecodeError:
            pass
        if self.data is not None:
            data['output'] = self.data

        # There could also be some data in the metadata,
        # this is an output of the condition script which
        # become an input for the fulfillment script
        try:
            if message['metadata'] and message['metadata']['data']:
                data['result'] = message['metadata']['data']
        except ValueError:
            pass
        # We can put pulic keys either in the keys or the data of zenroom
        data.update(self.keys)

        result = ZenroomSha256.run_zenroom(self.script,
                                           {},
                                           data)
        try:
            message['metadata']['result']
        except ValueError:
            raise MalformedMessageException()

        try:
            result = json.loads(result.output)
            # "Then print the string 'ok'" in zenroom produces a
            # dictionary of array with the string 'ok'
            # this is stored in result and compared against the content of
            # the metadata
            return result["output"][0] == message['metadata']['result']
        except JSONDecodeError:
            return False
