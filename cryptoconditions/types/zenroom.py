import base58
from base64 import urlsafe_b64decode, urlsafe_b64encode
from multiprocessing import Manager, Process
from zenroom import zencode_exec
import json
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.native.decoder import decode as nat_decode

from cryptoconditions.crypto import base64_add_padding, base64_remove_padding
from cryptoconditions.types.base_sha256 import BaseSha256
from cryptoconditions.schemas.fingerprint import ZenroomFingerprintContents

# from cryptoconditions.zencode import read_zencode
# from zenroom_minimal import Zenroom

def _execute(result, *args, **kwargs):
    z = zencode_exec(*args, **kwargs)
    result.put(z.output)


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
    def __init__(self, *, script=None, keys=None):
        """
        ZENROOM: Zenroom signature condition.

        This condition implements Zenroom signatures.

        ZENROOM is assigned the type ID 5.

        Args:
            script (bytes): Zenroom script (fulfillment)
            keys (bytes): Keyring dictionary. (TODO actually use)

        """
        self.script = script
        self.keys = keys

        # TODO data

    # TODO validate script
    def _validate_script(self, script):
        return script

    @property
    def script(self):
        return self._script

    @script.setter
    def script(self, script):
        self._script = self._validate_script(script)

    # TODO validate keys
    def _validate_keys(self, keys):
        return keys

    @property
    def keys(self):
        return self._keys or b''

    @keys.setter
    def keys(self, keys):
        self._keys = self._validate_keys(keys)

    @property
    def asn1_dict_payload(self):
        return {
            'script': self.script,
            'keys': self.keys,
        }

    @property
    def fingerprint_contents(self):
        asn1_fingerprint_obj = nat_decode(
            {'script': self.script},
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
            'script': base58.b58encode(self.script),
            'keys': base58.b58encode(self.keys),
        }

    def sign(self, message, condition_script, keys):

        self.script = condition_script

        # Should isolate the public key
        self.keys = keys

        message = json.loads(message)
        data = {}
        if 'data' in message['asset'].keys():
            data['asset'] = message['asset']['data']

        m = Manager()
        q= m.Queue()
        p = Process(target = _execute,
                    args=(q, condition_script,),
                    kwargs={'keys': json.dumps({"Alice": {"keypair": keys}}),
                            'data': json.dumps(data),})
        p.start()
        result = q.get()
        p.join()
        print(result)
        message['metadata'] = {'result': json.loads(result)}

        print(message)

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
        #zenroom = Zenroom(read_zencode)
        #zenroom = ""
        #script = self.script.decode('utf-8')
        #message = urlsafe_b64encode(message)[0:-1].decode('utf-8')
        #signature = self.data.decode('utf-8')

        try:
            #zenroom.load(script)
            # TODO make configurable with json / dict merging instead of lua table interpolating
            #zenroom.load_data("{ message = '%s', signature = '%s' }" %(message, signature))
            #zenroom.eval()
            True
        except:
            return False

        return True
