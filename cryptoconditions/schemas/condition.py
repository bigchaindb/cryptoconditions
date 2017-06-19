"""ASN.1 definitions for condition objects.

.. code-block:: text

    Crypto-Conditions DEFINITIONS AUTOMATIC TAGS ::= BEGIN

        -- Conditions

        Condition ::= CHOICE {
          preimageSha256   [0] SimpleSha256Condition,
          prefixSha256     [1] CompoundSha256Condition,
          thresholdSha256  [2] CompoundSha256Condition,
          rsaSha256        [3] SimpleSha256Condition,
          ed25519Sha256    [4] SimpleSha256Condition
        }

        SimpleSha256Condition ::= SEQUENCE {
          fingerprint          OCTET STRING (SIZE(32)),
          cost                 INTEGER (0..4294967295)
        }

        CompoundSha256Condition ::= SEQUENCE {
          fingerprint          OCTET STRING (SIZE(32)),
          cost                 INTEGER (0..4294967295),
          subtypes             ConditionTypes
        }

        ConditionTypes ::= BIT STRING {
          preImageSha256   (0),
          prefixSha256     (1),
          thresholdSha256  (2),
          rsaSha256        (3),
          ed25519Sha256    (4)
        }

    END

"""
from pyasn1.type.namedval import NamedValues
from pyasn1.type.univ import BitString, Choice, Integer, OctetString, Sequence
from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.constraint import ValueRangeConstraint, ValueSizeConstraint
from pyasn1.type.tag import (
    Tag, tagClassContext, tagFormatConstructed, tagFormatSimple)


class ConditionTypes(BitString):
    namedValues = NamedValues(
        ('preImageSha256', 0),
        ('prefixSha256', 1),
        ('thresholdSha256', 2),
        ('rsaSha256', 3),
        ('ed25519Sha256', 4),
    )


class CompoundSha256Condition(Sequence):
    componentType = NamedTypes(
        NamedType(
            'fingerprint',
            OctetString().subtype(
                subtypeSpec=ValueSizeConstraint(32, 32)).subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
        NamedType(
            'cost',
            Integer().subtype(
                subtypeSpec=ValueRangeConstraint(0, 4294967295)).subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
        NamedType(
            'subtypes',
            ConditionTypes().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 2))),
    )


class SimpleSha256Condition(Sequence):
    componentType = NamedTypes(
        NamedType(
            'fingerprint',
            OctetString().subtype(
                subtypeSpec=ValueSizeConstraint(32, 32)).subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
        NamedType(
            'cost',
            Integer().subtype(
                subtypeSpec=ValueRangeConstraint(0, 4294967295)).subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
    )


class Condition(Choice):
    componentType = NamedTypes(
        NamedType(
            'preimageSha256',
            SimpleSha256Condition().subtype(
                implicitTag=Tag(tagClassContext, tagFormatConstructed, 0))),
        NamedType(
            'prefixSha256',
            CompoundSha256Condition().subtype(
                implicitTag=Tag(tagClassContext, tagFormatConstructed, 1))),
        NamedType(
            'thresholdSha256',
            CompoundSha256Condition().subtype(
                implicitTag=Tag(tagClassContext, tagFormatConstructed, 2))),
        NamedType(
            'rsaSha256',
            SimpleSha256Condition().subtype(
                implicitTag=Tag(tagClassContext, tagFormatConstructed, 3))),
        NamedType(
            'ed25519Sha256',
            SimpleSha256Condition().subtype(
                implicitTag=Tag(tagClassContext, tagFormatConstructed, 4))),
    )
