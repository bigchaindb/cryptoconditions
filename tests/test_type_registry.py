import pytest


def test_find_type_by_id():
    from cryptoconditions.type_registry import (TypeRegistry,
                                                MAX_SAFE_INTEGER_JS)
    from cryptoconditions.exceptions import UnsupportedTypeError
    from cryptoconditions.types.preimage import PreimageSha256

    # test type_id > MAX_SAFE_INTEGER_JS
    with pytest.raises(UnsupportedTypeError):
        TypeRegistry.find_by_type_id(MAX_SAFE_INTEGER_JS + 1)

    # test type_id not in registered_types
    # we currently only support types from 0..4
    with pytest.raises(UnsupportedTypeError):
        TypeRegistry.find_by_type_id(MAX_SAFE_INTEGER_JS)

    # test type_id returns correct registered_type
    # type_id 0 is for preimage-sha-256
    registered_type = TypeRegistry.find_by_type_id(0)
    assert registered_type['name'] == PreimageSha256.TYPE_NAME


def test_find_by_name():
    from cryptoconditions.type_registry import TypeRegistry
    from cryptoconditions.exceptions import UnsupportedTypeError
    from cryptoconditions.types.preimage import PreimageSha256

    # test type name not in registered_types
    with pytest.raises(UnsupportedTypeError):
        TypeRegistry.find_by_name('magic')

    # test type name returns the correct registered_type
    registered_type = TypeRegistry.find_by_name('preimage-sha-256')
    assert registered_type['name'] == PreimageSha256.TYPE_NAME


def test_find_by_asn1_type():
    from cryptoconditions.type_registry import TypeRegistry
    from cryptoconditions.exceptions import UnsupportedTypeError
    from cryptoconditions.types.preimage import PreimageSha256

    # test asn1 type not in registered_types
    with pytest.raises(UnsupportedTypeError):
        TypeRegistry.find_by_asn1_type('magic')

    # test asn1 type returns the correct registered_type
    registered_type = TypeRegistry.find_by_asn1_type('preimageSha256')
    assert registered_type['asn1'] == PreimageSha256.TYPE_ASN1


def test_find_by_asn1_condition_type():
    from cryptoconditions.type_registry import TypeRegistry
    from cryptoconditions.exceptions import UnsupportedTypeError
    from cryptoconditions.types.preimage import PreimageSha256

    # test asn1 condition_type not in registered_types
    with pytest.raises(UnsupportedTypeError):
        TypeRegistry.find_by_asn1_condition_type('magic')

    # test asn1 condition_type returns the correct registered_type
    registered_type = TypeRegistry.find_by_asn1_condition_type(
        'preimageSha256Condition')
    assert registered_type['asn1_condition'] == \
        PreimageSha256.TYPE_ASN1_CONDITION


def test_find_by_asn1_fulfillment_type():
    from cryptoconditions.type_registry import TypeRegistry
    from cryptoconditions.exceptions import UnsupportedTypeError
    from cryptoconditions.types.preimage import PreimageSha256

    # test asn1 fulfillment_type not in registered_types
    with pytest.raises(UnsupportedTypeError):
        TypeRegistry.find_by_asn1_fulfillment_type('magic')

    # test asn1 fulfillment_type returns the correct registered_type
    registered_type = TypeRegistry.find_by_asn1_fulfillment_type(
        'preimageSha256Fulfillment')
    assert registered_type['asn1_fulfillment'] == \
        PreimageSha256.TYPE_ASN1_FULFILLMENT


def test_register_type():
    from cryptoconditions.type_registry import TypeRegistry

    class NewType:
        TYPE_ID = 1000
        TYPE_NAME = 'newType'
        TYPE_ASN1 = 'asn1NewType'
        TYPE_ASN1_CONDITION = 'asn1NewTypeCondition'
        TYPE_ASN1_FULFILLMENT = 'asn1NewTypeFulfillment'

    TypeRegistry.register_type(NewType)
    registered_type = TypeRegistry.find_by_type_id(1000)
    assert registered_type['class'] == NewType
