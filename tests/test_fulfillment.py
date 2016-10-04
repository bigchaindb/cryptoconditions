import binascii
from time import sleep

from math import ceil

import pytest

from cryptoconditions import \
    Condition, \
    Fulfillment, \
    PreimageSha256Fulfillment, \
    Ed25519Fulfillment, \
    ThresholdSha256Fulfillment, \
    InvertedThresholdSha256Fulfillment, \
    TimeoutFulfillment
from cryptoconditions.crypto import \
    Ed25519SigningKey as SigningKey, \
    Ed25519VerifyingKey as VerifyingKey
from cryptoconditions.types.timeout import timestamp

MESSAGE = b'Hello World! Conditions are here!'


class TestSha256Condition:
    def test_deserialize_condition(self, fulfillment_sha256):
        example_condition = fulfillment_sha256['condition_uri']
        condition = Condition.from_uri(example_condition)
        assert condition.serialize_uri() == fulfillment_sha256['condition_uri']

    def test_create_condition(self, fulfillment_sha256):
        sha256condition = Condition()
        sha256condition.type_id = PreimageSha256Fulfillment.TYPE_ID
        sha256condition.bitmask = PreimageSha256Fulfillment.FEATURE_BITMASK
        sha256condition.hash = binascii.unhexlify(fulfillment_sha256['condition_hash'])
        sha256condition.max_fulfillment_length = 0
        assert sha256condition.serialize_uri() == fulfillment_sha256['condition_uri']


class TestSha256Fulfillment:
    def test_deserialize_and_validate_fulfillment(self, fulfillment_sha256):
        fulfillment = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])

        assert fulfillment.serialize_uri() == fulfillment_sha256['fulfillment_uri']
        assert fulfillment.condition.serialize_uri() == fulfillment_sha256['condition_uri']
        assert fulfillment.validate()

    def test_fulfillment_serialize_to_dict(self, fulfillment_sha256):
        fulfillment = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

    def test_deserialize_condition_and_validate_fulfillment(self, fulfillment_sha256):
        condition = Condition.from_uri(fulfillment_sha256['condition_uri'])
        fulfillment = PreimageSha256Fulfillment()
        fulfillment.preimage = ''

        assert fulfillment.serialize_uri() == fulfillment_sha256['fulfillment_uri']
        assert fulfillment.condition.serialize_uri() == condition.serialize_uri()
        assert fulfillment.validate()
        assert fulfillment.validate() and fulfillment.condition.serialize_uri() == condition.serialize_uri()

    def test_condition_from_fulfillment(self):
        fulfillment = PreimageSha256Fulfillment()
        with pytest.raises(ValueError):
            fulfillment.condition

        fulfillment.preimage = 'Hello World!'
        condition = fulfillment.condition

        verify_fulfillment = PreimageSha256Fulfillment()
        verify_fulfillment.preimage = 'Hello World!'
        assert verify_fulfillment.condition.serialize_uri() == condition.serialize_uri()
        assert verify_fulfillment.validate()


class TestEd25519Sha256Fulfillment:
    def test_ilp_keys(self, sk_ilp, vk_ilp):
        sk = SigningKey(sk_ilp['b58'])
        assert sk.encode(encoding='base64') == sk_ilp['b64']
        assert binascii.hexlify(sk.encode(encoding='bytes')[:32]) == sk_ilp['hex']

        vk = VerifyingKey(vk_ilp['b58'])
        assert vk.encode(encoding='base64') == vk_ilp['b64']
        assert binascii.hexlify(vk.encode(encoding='bytes')) == vk_ilp['hex']

    def test_create(self, vk_ilp):
        fulfillment1 = Ed25519Fulfillment(public_key=vk_ilp['b58'])
        fulfillment2 = Ed25519Fulfillment(VerifyingKey(vk_ilp['b58']))
        assert fulfillment1.condition.serialize_uri() == fulfillment2.condition.serialize_uri()

    def test_serialize_condition_and_validate_fulfillment(self, sk_ilp, vk_ilp, fulfillment_ed25519):
        sk = SigningKey(sk_ilp['b58'])
        vk = VerifyingKey(vk_ilp['b58'])

        fulfillment = Ed25519Fulfillment(public_key=vk)

        assert fulfillment.condition.serialize_uri() == fulfillment_ed25519['condition_uri']
        assert binascii.hexlify(fulfillment.condition.hash) == fulfillment_ed25519['condition_hash']

        # ED25519-SHA256 condition not fulfilled
        assert fulfillment.validate() == False

        # Fulfill an ED25519-SHA256 condition
        fulfillment.sign(MESSAGE, sk)

        assert fulfillment.serialize_uri() == fulfillment_ed25519['fulfillment_uri']
        assert fulfillment.validate(MESSAGE)

    def test_deserialize_condition(self, fulfillment_ed25519):
        deserialized_condition = Condition.from_uri(fulfillment_ed25519['condition_uri'])

        assert deserialized_condition.serialize_uri() == fulfillment_ed25519['condition_uri']
        assert binascii.hexlify(deserialized_condition.hash) == fulfillment_ed25519['condition_hash']

    def test_serialize_signed_dict_to_fulfillment(self, fulfillment_ed25519):
        fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        assert fulfillment.to_dict()== \
            {'bitmask': 32,
             'public_key': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
             'signature': '4eCt6SFPCzLQSAoQGW7CTu3MHdLj6FezSpjktE7tHsYGJ4pNSUnpHtV9XgdHF2XYd62M9fTJ4WYdhTVck27qNoHj',
             'type': 'fulfillment',
             'type_id': 4}

        assert fulfillment.validate(MESSAGE) == True

    def test_serialize_unsigned_dict_to_fulfillment(self, vk_ilp):
        fulfillment = Ed25519Fulfillment(public_key=vk_ilp['b58'])

        assert fulfillment.to_dict() == \
            {'bitmask': 32,
             'public_key': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
             'signature': None,
             'type': 'fulfillment',
             'type_id': 4}
        assert fulfillment.validate(MESSAGE) == False

    def test_deserialize_signed_dict_to_fulfillment(self, fulfillment_ed25519):
        fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.serialize_uri() == fulfillment_ed25519['fulfillment_uri']
        assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

    def test_deserialize_unsigned_dict_to_fulfillment(self, vk_ilp):
        fulfillment = Ed25519Fulfillment(public_key=vk_ilp['b58'])
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

    def test_serialize_deserialize_condition(self, vk_ilp):
        vk = VerifyingKey(vk_ilp['b58'])

        fulfillment = Ed25519Fulfillment(public_key=vk)

        condition = fulfillment.condition
        deserialized_condition = Condition.from_uri(condition.serialize_uri())

        assert deserialized_condition.bitmask == condition.bitmask
        assert deserialized_condition.hash == condition.hash
        assert deserialized_condition.max_fulfillment_length == condition.max_fulfillment_length
        assert deserialized_condition.serialize_uri() == condition.serialize_uri()

    def test_deserialize_fulfillment(self, vk_ilp, fulfillment_ed25519):
        fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        assert isinstance(fulfillment, Ed25519Fulfillment)
        assert fulfillment.serialize_uri() == fulfillment_ed25519['fulfillment_uri']
        assert fulfillment.condition.serialize_uri() == fulfillment_ed25519['condition_uri']
        assert binascii.hexlify(fulfillment.condition.hash) == fulfillment_ed25519['condition_hash']
        assert fulfillment.public_key.encode(encoding='hex') == vk_ilp['hex']
        assert fulfillment.validate(MESSAGE)

    def test_deserialize_fulfillment_2(self, vk_ilp, fulfillment_ed25519_2):
        fulfillment = Fulfillment.from_uri(fulfillment_ed25519_2['fulfillment_uri'])

        assert isinstance(fulfillment, Ed25519Fulfillment)
        assert fulfillment.serialize_uri() == fulfillment_ed25519_2['fulfillment_uri']
        assert fulfillment.condition.serialize_uri() == fulfillment_ed25519_2['condition_uri']
        assert binascii.hexlify(fulfillment.condition.hash) == fulfillment_ed25519_2['condition_hash']
        assert fulfillment.public_key.encode(encoding='hex') == vk_ilp[2]['hex']
        assert fulfillment.validate(MESSAGE)

    def test_serialize_deserialize_fulfillment(self, sk_ilp, vk_ilp):
        sk = SigningKey(sk_ilp['b58'])
        vk = VerifyingKey(vk_ilp['b58'])

        fulfillment = Ed25519Fulfillment(public_key=vk)
        fulfillment.sign(MESSAGE, sk)

        assert fulfillment.validate(MESSAGE)

        deserialized_fulfillment = Fulfillment.from_uri(fulfillment.serialize_uri())
        assert isinstance(deserialized_fulfillment, Ed25519Fulfillment)
        assert deserialized_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        assert deserialized_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert deserialized_fulfillment.public_key.encode(encoding='bytes') == \
                fulfillment.public_key.encode(encoding='bytes')
        assert deserialized_fulfillment.validate(MESSAGE)


class TestThresholdSha256Fulfillment:

    def create_fulfillment_ed25519sha256(self, sk_ilp, vk_ilp):
        sk = SigningKey(sk_ilp['b58'])
        vk = VerifyingKey(vk_ilp['b58'])

        fulfillment = Ed25519Fulfillment(public_key=vk)
        fulfillment.sign(MESSAGE, sk)
        return fulfillment

    def test_serialize_condition_and_validate_fulfillment(self,
                                                          fulfillment_sha256,
                                                          fulfillment_ed25519,
                                                          fulfillment_threshold):

        ilp_fulfillment_ed25519 = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])
        ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])

        assert ilp_fulfillment_ed25519.validate(MESSAGE) == True
        assert ilp_fulfillment_sha.validate(MESSAGE) == True

        threshold = 1

        # Create a threshold condition
        fulfillment = ThresholdSha256Fulfillment(threshold=threshold)
        fulfillment.add_subfulfillment(ilp_fulfillment_ed25519)
        fulfillment.add_subfulfillment(ilp_fulfillment_sha)

        assert fulfillment.condition.serialize_uri() == fulfillment_threshold['condition_uri']
        # Note: If there are more than enough fulfilled subconditions, shorter
        # fulfillments will be chosen over longer ones.
        # thresholdFulfillmentUri.length === 65
        assert fulfillment.serialize_uri() == fulfillment_threshold['fulfillment_uri']
        assert fulfillment.validate(MESSAGE)

    def test_deserialize_fulfillment(self, fulfillment_threshold):
        num_fulfillments = 2
        threshold = 1

        fulfillment = Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri'])

        assert isinstance(fulfillment, ThresholdSha256Fulfillment)
        assert fulfillment.threshold == threshold
        assert len([f for f in fulfillment.subconditions if f['type'] == 'fulfillment']) == threshold
        assert fulfillment.serialize_uri() == fulfillment_threshold['fulfillment_uri']
        assert len(fulfillment.subconditions) == num_fulfillments
        assert fulfillment.validate(MESSAGE)

    def test_serialize_signed_dict_to_fulfillment(self, fulfillment_threshold):
        fulfillment = Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri'])

        assert fulfillment.to_dict() == \
            {'bitmask': 43,
             'subfulfillments': [{'bitmask': 3,
                                  'preimage': '',
                                  'type': 'fulfillment',
                                  'type_id': 0,
                                  'weight': 1},
                                 {'bitmask': 32,
                                  'hash': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
                                  'max_fulfillment_length': 96,
                                  'type': 'condition',
                                  'type_id': 4,
                                  'weight': 1}],
             'threshold': 1,
             'type': 'fulfillment',
             'type_id': 2}

    def test_serialize_unsigned_dict_to_fulfillment(self, vk_ilp):
        fulfillment = ThresholdSha256Fulfillment(threshold=1)
        fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))
        fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))

        assert fulfillment.to_dict() == \
            {'bitmask': 41,
             'subfulfillments': [{'bitmask': 32,
                                  'public_key': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
                                  'signature': None,
                                  'type': 'fulfillment',
                                  'type_id': 4,
                                  'weight': 1},
                                 {'bitmask': 32,
                                  'public_key': 'Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU',
                                  'signature': None,
                                  'type': 'fulfillment',
                                  'type_id': 4,
                                  'weight': 1}],
             'threshold': 1,
             'type': 'fulfillment',
             'type_id': 2}

    def test_deserialize_signed_dict_to_fulfillment(self, fulfillment_threshold):
        fulfillment = Fulfillment.from_uri(fulfillment_threshold['fulfillment_uri'])
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.serialize_uri() == fulfillment_threshold['fulfillment_uri']
        assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

    def test_deserialize_unsigned_dict_to_fulfillment(self, vk_ilp):
        fulfillment = ThresholdSha256Fulfillment(threshold=1)
        fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))
        fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

    def test_weights(self, fulfillment_ed25519):
        ilp_fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        fulfillment1 = ThresholdSha256Fulfillment(threshold=2)
        fulfillment1.add_subfulfillment(ilp_fulfillment, weight=2)
        parsed_fulfillment1 = fulfillment1.from_dict(fulfillment1.to_dict())

        assert parsed_fulfillment1.condition.serialize_uri() == fulfillment1.condition.serialize_uri()
        assert parsed_fulfillment1.to_dict() == fulfillment1.to_dict()
        assert parsed_fulfillment1.subconditions[0]['weight'] == 2
        assert parsed_fulfillment1.validate(MESSAGE) is True

        fulfillment2 = ThresholdSha256Fulfillment(threshold=3)
        fulfillment2.add_subfulfillment(ilp_fulfillment, weight=2)
        parsed_fulfillment2 = fulfillment1.from_dict(fulfillment2.to_dict())

        assert parsed_fulfillment2.subconditions[0]['weight'] == 2
        assert parsed_fulfillment2.validate(MESSAGE) is False

        fulfillment3 = ThresholdSha256Fulfillment(threshold=3)
        fulfillment3.add_subfulfillment(ilp_fulfillment, weight=3)
        parsed_fulfillment3 = fulfillment1.from_dict(fulfillment3.to_dict())

        assert parsed_fulfillment3.condition.serialize_uri() == fulfillment3.condition.serialize_uri()
        assert not (fulfillment3.condition.serialize_uri() == fulfillment1.condition.serialize_uri())
        assert parsed_fulfillment3.validate(MESSAGE) is True

        fulfillment4 = ThresholdSha256Fulfillment(threshold=2)
        with pytest.raises(ValueError):
            fulfillment4.add_subfulfillment(ilp_fulfillment, weight=-2)

    def test_serialize_deserialize_fulfillment(self,
                                               fulfillment_ed25519):
        ilp_fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])
        num_fulfillments = 20
        threshold = ceil(num_fulfillments * 2 / 3)

        # Create a threshold condition
        fulfillment = ThresholdSha256Fulfillment(threshold=threshold)
        for i in range(num_fulfillments):
            fulfillment.add_subfulfillment(ilp_fulfillment)

        fulfillment_uri = fulfillment.serialize_uri()

        assert fulfillment.validate(MESSAGE)
        deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        assert isinstance(deserialized_fulfillment, ThresholdSha256Fulfillment)
        assert deserialized_fulfillment.threshold == threshold
        assert len([f for f in deserialized_fulfillment.subconditions if f['type'] == 'fulfillment']) == threshold
        assert len(deserialized_fulfillment.subconditions) == num_fulfillments
        assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        assert deserialized_fulfillment.validate(MESSAGE)

    def test_fulfillment_didnt_reach_threshold(self, vk_ilp, fulfillment_ed25519):
        ilp_fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])
        threshold = 10

        # Create a threshold condition
        fulfillment = ThresholdSha256Fulfillment(threshold=threshold)

        for i in range(threshold - 1):
            fulfillment.add_subfulfillment(ilp_fulfillment)

        with pytest.raises(KeyError):
            fulfillment.serialize_uri()

        assert fulfillment.validate(MESSAGE) is False

        fulfillment.add_subfulfillment(ilp_fulfillment)

        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment.validate(MESSAGE)

        deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        assert isinstance(deserialized_fulfillment, ThresholdSha256Fulfillment)
        assert deserialized_fulfillment.threshold == threshold
        assert len([f for f in deserialized_fulfillment.subconditions if f['type'] == 'fulfillment']) == threshold
        assert len(deserialized_fulfillment.subconditions) == threshold
        assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        assert deserialized_fulfillment.validate(MESSAGE)

        fulfillment.add_subfulfillment(Ed25519Fulfillment(public_key=VerifyingKey(vk_ilp['b58'])))

        assert fulfillment.validate(MESSAGE) == True

    def test_fulfillment_nested_and_or(self,
                                       fulfillment_sha256,
                                       fulfillment_ed25519,
                                       fulfillment_threshold_nested_and_or):
        ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        # 2-of-2 (AND with 2 inputs)
        fulfillment = ThresholdSha256Fulfillment(threshold=2)
        fulfillment.add_subfulfillment(ilp_fulfillment_sha)

        assert fulfillment.validate(MESSAGE) is False

        # 1-of-2 (OR with 2 inputs)
        nested_fulfillment = ThresholdSha256Fulfillment(threshold=1)
        nested_fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        assert nested_fulfillment.validate(MESSAGE) is True
        nested_fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        assert nested_fulfillment.validate(MESSAGE) is True

        fulfillment.add_subfulfillment(nested_fulfillment)
        assert fulfillment.validate(MESSAGE) is True

        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment.condition_uri == fulfillment_threshold_nested_and_or['condition_uri']
        assert fulfillment_uri == fulfillment_threshold_nested_and_or['fulfillment_uri']

        print(fulfillment_uri)
        deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        condition_uri = fulfillment.condition.serialize_uri()
        deserialized_condition = Condition.from_uri(condition_uri)

        assert isinstance(deserialized_fulfillment, ThresholdSha256Fulfillment)
        assert deserialized_fulfillment.threshold == 2
        assert len(deserialized_fulfillment.subconditions) == 2
        assert len(deserialized_fulfillment.subconditions[1]['body'].subconditions) == 2
        assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        assert deserialized_fulfillment.validate(MESSAGE)
        assert deserialized_condition.serialize_uri() == condition_uri
        vk = ilp_fulfillment_ed.public_key.encode(encoding='base58')
        assert len(fulfillment.get_subcondition_from_vk(vk)) == 2
        assert len(deserialized_fulfillment.get_subcondition_from_vk(vk)) == 1

    def test_fulfillment_nested(self,
                                fulfillment_sha256,
                                fulfillment_ed25519_2, ):
        ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        ilp_fulfillment_ed1 = Fulfillment.from_uri(fulfillment_ed25519_2['fulfillment_uri'])

        # 2-of-2 (AND with 2 inputs)
        fulfillment = ThresholdSha256Fulfillment(threshold=2)
        fulfillment.add_subfulfillment(ilp_fulfillment_sha)

        max_depth = 6

        def add_nested_fulfillment(parent, current_depth=0):
            current_depth += 1
            child = ThresholdSha256Fulfillment(threshold=1)
            if current_depth < max_depth:
                add_nested_fulfillment(child, current_depth)
            else:
                child.add_subfulfillment(ilp_fulfillment_ed1)
            parent.add_subfulfillment(child)
            return parent

        fulfillment = add_nested_fulfillment(fulfillment)

        assert fulfillment.validate(MESSAGE) is True
        assert len(fulfillment.subconditions) == 2
        assert isinstance(fulfillment.subconditions[1]['body'], ThresholdSha256Fulfillment)
        assert isinstance(fulfillment.subconditions[1]['body'].subconditions[0]['body'], ThresholdSha256Fulfillment)

        fulfillment_uri = fulfillment.serialize_uri()
        deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        condition_uri = fulfillment.condition.serialize_uri()
        deserialized_condition = Condition.from_uri(condition_uri)

        assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        assert deserialized_fulfillment.validate(MESSAGE) is True
        assert deserialized_condition.serialize_uri() == condition_uri


class TestInvertedThresholdSha256Fulfillment:

    def test_serialize_condition_and_validate_fulfillment(self,
                                                          fulfillment_ed25519):
        ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        fulfillment = InvertedThresholdSha256Fulfillment(threshold=1)
        fulfillment.add_subfulfillment(ilp_fulfillment_ed)
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.condition_uri == fulfillment.condition_uri
        assert parsed_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        assert parsed_fulfillment.validate(MESSAGE) is False
        assert parsed_fulfillment.validate() is True
        assert isinstance(parsed_fulfillment, InvertedThresholdSha256Fulfillment)


class TestTimeoutFulfillment:

    def test_serialize_condition_and_validate_fulfillment(self):

        fulfillment = TimeoutFulfillment(expire_time=timestamp())
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.condition_uri == fulfillment.condition_uri
        assert parsed_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        assert parsed_fulfillment.validate(now=timestamp()) is False

        fulfillment = TimeoutFulfillment(expire_time=str(float(timestamp()) + 1000))
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.condition_uri == fulfillment.condition_uri
        assert parsed_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        assert parsed_fulfillment.validate(now=timestamp()) is True


class TestEscrow:
    def create_fulfillment_ed25519sha256(self, sk_ilp, vk_ilp):
        sk = SigningKey(sk_ilp['b58'])
        vk = VerifyingKey(vk_ilp['b58'])

        fulfillment = Ed25519Fulfillment(public_key=vk)
        fulfillment.sign(MESSAGE, sk)
        return fulfillment

    def test_serialize_condition_and_validate_fulfillment(self,
                                                          fulfillment_sha256,
                                                          fulfillment_ed25519):
        ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        fulfillment_escrow = ThresholdSha256Fulfillment(threshold=1)
        fulfillment_timeout = TimeoutFulfillment(expire_time=str(float(timestamp()) + 1000))
        fulfillment_timeout_inverted = InvertedThresholdSha256Fulfillment(threshold=1)
        fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

        fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_execute.add_subfulfillment(ilp_fulfillment_ed)
        fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        assert fulfillment_and_execute.validate(MESSAGE, now=timestamp()) is True

        fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
        fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        # timeout has not occured (over about 1000 seconds)
        assert fulfillment_and_abort.validate(MESSAGE, now=timestamp()) is False

        fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
        fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

        parsed_fulfillment = fulfillment_escrow.from_dict(fulfillment_escrow.to_dict())

        assert parsed_fulfillment.condition_uri == fulfillment_escrow.condition_uri
        assert parsed_fulfillment.serialize_uri() == fulfillment_escrow.serialize_uri()
        assert parsed_fulfillment.validate(MESSAGE, now=timestamp()) is True

    def test_escrow_execute(self, fulfillment_sha256, fulfillment_ed25519):

        ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        time_sleep = 3

        fulfillment_escrow = ThresholdSha256Fulfillment(threshold=1)
        fulfillment_timeout = TimeoutFulfillment(expire_time=str(float(timestamp()) + time_sleep))
        fulfillment_timeout_inverted = InvertedThresholdSha256Fulfillment(threshold=1)
        fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

        # fulfill execute branch
        fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_execute.add_subfulfillment(ilp_fulfillment_ed)
        fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        # do not fulfill abort branch
        fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_abort.add_subcondition(ilp_fulfillment_sha.condition)
        fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
        fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

        # in-time validation
        assert fulfillment_escrow.validate(MESSAGE, now=timestamp()) is True

        sleep(3)
        # out-of-time validation
        assert fulfillment_escrow.validate(MESSAGE, now=timestamp()) is False

    def test_escrow_abort(self, fulfillment_sha256, fulfillment_ed25519):
        ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        time_sleep = 0

        fulfillment_escrow = ThresholdSha256Fulfillment(threshold=1)
        fulfillment_timeout = TimeoutFulfillment(expire_time=str(float(timestamp()) + time_sleep))
        fulfillment_timeout_inverted = InvertedThresholdSha256Fulfillment(threshold=1)
        fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

        # do not fulfill execute branch
        fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_execute.add_subcondition(ilp_fulfillment_ed.condition)
        fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
        fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        fulfillment_escrow.add_subfulfillment(fulfillment_and_execute)
        fulfillment_escrow.add_subfulfillment(fulfillment_and_abort)

        # out-of-time validation
        assert fulfillment_escrow.validate(MESSAGE, now=timestamp()) is True

    def test_escrow_execute_abort(self, fulfillment_sha256, fulfillment_ed25519):
        ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        time_sleep = 3

        fulfillment_escrow_execute = ThresholdSha256Fulfillment(threshold=1)
        fulfillment_timeout = TimeoutFulfillment(expire_time=str(float(timestamp()) + time_sleep))
        fulfillment_timeout_inverted = InvertedThresholdSha256Fulfillment(threshold=1)
        fulfillment_timeout_inverted.add_subfulfillment(fulfillment_timeout)

        # fulfill execute branch
        fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_execute.add_subfulfillment(ilp_fulfillment_ed)
        fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        # do not fulfill abort branch
        fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_abort.add_subcondition(ilp_fulfillment_sha.condition)
        fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        fulfillment_escrow_execute.add_subfulfillment(fulfillment_and_execute)
        fulfillment_escrow_execute.add_subfulfillment(fulfillment_and_abort)

        # in-time validation
        assert fulfillment_escrow_execute.validate(MESSAGE, now=timestamp()) is True

        sleep(3)
        # out-of-time validation
        assert fulfillment_escrow_execute.validate(MESSAGE, now=timestamp()) is False

        fulfillment_escrow_abort = ThresholdSha256Fulfillment(threshold=1)

        # do not fulfill execute branch
        fulfillment_and_execute = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_execute.add_subcondition(ilp_fulfillment_ed.condition)
        fulfillment_and_execute.add_subfulfillment(fulfillment_timeout)

        # fulfill abort branch
        fulfillment_and_abort = ThresholdSha256Fulfillment(threshold=2)
        fulfillment_and_abort.add_subfulfillment(ilp_fulfillment_sha)
        fulfillment_and_abort.add_subfulfillment(fulfillment_timeout_inverted)

        fulfillment_escrow_abort.add_subfulfillment(fulfillment_and_execute)
        fulfillment_escrow_abort.add_subfulfillment(fulfillment_and_abort)

        assert fulfillment_escrow_abort.validate(MESSAGE, now=timestamp()) is True

