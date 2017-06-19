"""ASN.1 definitions for fingerprint objects.

.. code-block:: text

    Crypto-Conditions DEFINITIONS AUTOMATIC TAGS ::= BEGIN

        -- Fingerprint Content

        -- The PREIMAGE-SHA-256 condition fingerprint content is not DER
        -- encoded
        -- The fingerprint content is the preimage

        PrefixFingerprintContents ::= SEQUENCE {
          prefix               OCTET STRING,
          maxMessageLength     INTEGER (0..4294967295),
          subcondition         Condition
        }

        ThresholdFingerprintContents ::= SEQUENCE {
          threshold            INTEGER (1..65535),
          subconditions        SET OF Condition
        }

        RsaFingerprintContents ::= SEQUENCE {
          modulus              OCTET STRING
        }

        Ed25519FingerprintContents ::= SEQUENCE {
          publicKey            OCTET STRING (SIZE(32))
        }

    END

"""
from pyasn1.type.univ import Integer, OctetString, Sequence, SetOf
from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.constraint import ValueRangeConstraint, ValueSizeConstraint
from pyasn1.type.tag import (
    Tag, tagClassContext, tagFormatConstructed, tagFormatSimple)

from cryptoconditions.schemas.condition import Condition


class Ed25519FingerprintContents(Sequence):
    componentType = NamedTypes(
        NamedType(
            'publicKey',
            OctetString().subtype(
                subtypeSpec=ValueSizeConstraint(32, 32)).subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
    )


class PrefixFingerprintContents(Sequence):
    componentType = NamedTypes(
        NamedType(
            'prefix',
            OctetString().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
        NamedType(
            'maxMessageLength',
            Integer().subtype(
                subtypeSpec=ValueRangeConstraint(0, 4294967295)).subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
        NamedType(
            'subcondition',
            Condition().subtype(
                implicitTag=Tag(tagClassContext, tagFormatConstructed, 2))),
    )


class RsaFingerprintContents(Sequence):
    componentType = NamedTypes(
        NamedType(
            'modulus',
            OctetString().subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
    )


class ThresholdFingerprintContents(Sequence):
    componentType = NamedTypes(
        NamedType(
            'threshold',
            Integer().subtype(
                subtypeSpec=ValueRangeConstraint(1, 65535)).subtype(
                    implicitTag=Tag(tagClassContext, tagFormatSimple, 0))),
        NamedType(
            'subconditions',
            SetOf(componentType=Condition()).subtype(
                implicitTag=Tag(tagClassContext, tagFormatSimple, 1))),
    )
