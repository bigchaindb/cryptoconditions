import pytest

from cryptoconditions import \
    Condition, \
    Fulfillment, \
    Ed25519Sha256, \
    ThresholdSha256
from cryptoconditions.crypto import Ed25519VerifyingKey as VerifyingKey

MESSAGE = b'Hello World! Conditions are here!'


def test_fulfillment_uri_invalid():
    from cryptoconditions import Fulfillment
    with pytest.raises(TypeError) as exc:
        Fulfillment.from_uri(123)
    assert exc.value.args == ('Serialized fulfillment must be a string',)


@pytest.mark.skip(reason='upgrade to version 02 of the draft')
class TestSha256Fulfillment:

    def test_fulfillment_serialize_to_dict(self, fulfillment_sha256):
        fulfillment = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.serialize_uri() == fulfillment.serialize_uri()
        assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert parsed_fulfillment.to_dict() == fulfillment.to_dict()


@pytest.mark.skip(reason='upgrade to version 02 of the draft')
class TestEd25519Sha256Fulfillment:

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
        fulfillment = Ed25519Sha256(public_key=vk_ilp['b58'])

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
        fulfillment = Ed25519Sha256(public_key=vk_ilp['b58'])
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert parsed_fulfillment.to_dict() == fulfillment.to_dict()


@pytest.mark.skip(reason='upgrade to version 02 of the draft')
class TestThresholdSha256Fulfillment:

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
        fulfillment = ThresholdSha256(threshold=1)
        fulfillment.add_subfulfillment(Ed25519Sha256(public_key=VerifyingKey(vk_ilp['b58'])))
        fulfillment.add_subfulfillment(Ed25519Sha256(public_key=VerifyingKey(vk_ilp['b58'])))

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
        fulfillment = ThresholdSha256(threshold=1)
        fulfillment.add_subfulfillment(Ed25519Sha256(public_key=VerifyingKey(vk_ilp['b58'])))
        fulfillment.add_subfulfillment(Ed25519Sha256(public_key=VerifyingKey(vk_ilp['b58'])))
        parsed_fulfillment = fulfillment.from_dict(fulfillment.to_dict())

        assert parsed_fulfillment.condition.serialize_uri() == fulfillment.condition.serialize_uri()
        assert parsed_fulfillment.to_dict() == fulfillment.to_dict()

    def test_fulfillment_didnt_reach_threshold(self, vk_ilp, fulfillment_ed25519):
        ilp_fulfillment = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])
        threshold = 10

        # Create a threshold condition
        fulfillment = ThresholdSha256(threshold=threshold)

        for i in range(threshold - 1):
            fulfillment.add_subfulfillment(ilp_fulfillment)

        with pytest.raises(KeyError):
            fulfillment.serialize_uri()

        assert fulfillment.validate(MESSAGE) is False

        fulfillment.add_subfulfillment(ilp_fulfillment)

        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment.validate(MESSAGE)

        deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        assert isinstance(deserialized_fulfillment, ThresholdSha256)
        assert deserialized_fulfillment.threshold == threshold
        assert len([f for f in deserialized_fulfillment.subconditions if f['type'] == 'fulfillment']) == threshold
        assert len(deserialized_fulfillment.subconditions) == threshold
        assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        assert deserialized_fulfillment.validate(MESSAGE)

        fulfillment.add_subfulfillment(Ed25519Sha256(public_key=VerifyingKey(vk_ilp['b58'])))

        assert fulfillment.validate(MESSAGE) == True

    def test_fulfillment_nested_and_or(self,
                                       fulfillment_sha256,
                                       fulfillment_ed25519,
                                       fulfillment_threshold_nested_and_or):
        ilp_fulfillment_sha = Fulfillment.from_uri(fulfillment_sha256['fulfillment_uri'])
        ilp_fulfillment_ed = Fulfillment.from_uri(fulfillment_ed25519['fulfillment_uri'])

        # 2-of-2 (AND with 2 inputs)
        fulfillment = ThresholdSha256(threshold=2)
        fulfillment.add_subfulfillment(ilp_fulfillment_sha)

        assert fulfillment.validate(MESSAGE) is False

        # 1-of-2 (OR with 2 inputs)
        nested_fulfillment = ThresholdSha256(threshold=1)
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

        assert isinstance(deserialized_fulfillment, ThresholdSha256)
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
        fulfillment = ThresholdSha256(threshold=2)
        fulfillment.add_subfulfillment(ilp_fulfillment_sha)

        max_depth = 6

        def add_nested_fulfillment(parent, current_depth=0):
            current_depth += 1
            child = ThresholdSha256(threshold=1)
            if current_depth < max_depth:
                add_nested_fulfillment(child, current_depth)
            else:
                child.add_subfulfillment(ilp_fulfillment_ed1)
            parent.add_subfulfillment(child)
            return parent

        fulfillment = add_nested_fulfillment(fulfillment)

        assert fulfillment.validate(MESSAGE) is True
        assert len(fulfillment.subconditions) == 2
        assert isinstance(fulfillment.subconditions[1]['body'], ThresholdSha256)
        assert isinstance(fulfillment.subconditions[1]['body'].subconditions[0]['body'], ThresholdSha256)

        fulfillment_uri = fulfillment.serialize_uri()
        deserialized_fulfillment = Fulfillment.from_uri(fulfillment_uri)

        condition_uri = fulfillment.condition.serialize_uri()
        deserialized_condition = Condition.from_uri(condition_uri)

        assert deserialized_fulfillment.serialize_uri() == fulfillment_uri
        assert deserialized_fulfillment.validate(MESSAGE) is True
        assert deserialized_condition.serialize_uri() == condition_uri
