"""The tests therein are meant to test the generated test vectors that
can be found at https://github.com/rfcs/crypto-conditions. These test
vectors are examples of valid crypto-conditions and their fulfillments.

For each test vector, the following should be tested:

* Parse ``conditionBinary``, serialize as a URI, should match
  ``conditionUri``.
* Parse ``conditionUri``, serialize as binary, should match
  ``conditionBinary``.
* Parse ``fulfillment``, serialize fulfillment, should match
  ``fulfillment``.
* Parse ``fulfillment`` and validate, should return ``True``.
* Parse ``fulfillment`` and generate the fingerprint contents.
* Parse ``fulfillment``, generate the condition, serialize the
  condition as a URI, should match ``conditionUri``.
* Create fulfillment from ``json``, serialize fulfillment, should match
  ``fulfillment``.

"""
from base64 import urlsafe_b64decode


class TestVector:
    def test_condition_from_binary_to_serialize_uri(self, test_vector):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(test_vector.condition_binary)
        assert condition.serialize_uri() == test_vector.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, test_vector):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(test_vector.condition_uri)
        assert condition.serialize_binary() == test_vector.condition_binary

    def test_fulfillment_parsing(self, test_vector):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(test_vector.fulfillment)
        assert fulfillment.serialize_uri() == test_vector.fulfillment

    def test_fulfillment_validation(self, test_vector):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(test_vector.fulfillment)
        assert fulfillment.validate(message=test_vector.message)

    def test_condition_validation_from_binary(self, test_vector):
        """

        1. Parse condition.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(test_vector.condition_binary)
        assert condition.validate()

    def test_condition_validation_from_uri(self, test_vector):
        """

        1. Parse condition.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(test_vector.condition_uri)
        assert condition.validate()

    def test_fulfillment_fingerprint_generation(self, test_vector):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(test_vector.fulfillment)
        assert fulfillment.fingerprint_contents == test_vector.fingerprint_contents

    def test_fulfillment_condition_generation(self, test_vector):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(test_vector.fulfillment)
        condition = fulfillment.condition
        assert condition.serialize_uri() == test_vector.condition_uri

    def test_fulfillment_parsing_from_json(self, test_vector):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(test_vector.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == test_vector.fulfillment


###############################################################################
#                                                                             #
#                           Minimal cases                                     #
#                                                                             #
###############################################################################
class TestMinimalPreimage:
    def test_condition_from_binary_to_serialize_uri(self, minimal_preimage):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        buffer_ = minimal_preimage.condition_binary
        condition = Condition.from_binary(buffer_)
        assert condition.serialize_uri() == minimal_preimage.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, minimal_preimage):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(minimal_preimage.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == minimal_preimage.condition_binary

    def test_fulfillment_parsing(self, minimal_preimage):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_preimage.fulfillment)
        assert fulfillment.serialize_uri() == minimal_preimage.fulfillment

    def test_fulfillment_validation(self, minimal_preimage):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_preimage.fulfillment)
        assert fulfillment.validate(minimal_preimage.message)

    def test_condition_validation(self, minimal_preimage):
        """

        1. Parse condition.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(minimal_preimage.condition_binary)
        assert condition.validate()

    def test_fulfillment_fingerprint_generation(self, minimal_preimage):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_preimage.fulfillment)
        assert fulfillment.fingerprint_contents == minimal_preimage.fingerprint_contents

    def test_fulfillment_condition_generation(self, minimal_preimage):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_preimage.fulfillment)
        condition = fulfillment.condition
        assert condition.serialize_uri() == minimal_preimage.condition_uri

    def test_fulfillment_parsing_from_json(self, minimal_preimage):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(minimal_preimage.json)
        assert fulfillment.serialize_uri() == minimal_preimage.fulfillment


class TestMinimalPrefix:
    def test_condition_from_binary_to_serialize_uri(self, minimal_prefix):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(minimal_prefix.condition_binary)
        assert condition.serialize_uri() == minimal_prefix.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, minimal_prefix):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(minimal_prefix.condition_uri)
        assert condition.serialize_binary() == minimal_prefix.condition_binary

    def test_fulfillment_parsing(self, minimal_prefix):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_prefix.fulfillment)
        assert fulfillment.serialize_uri() == minimal_prefix.fulfillment

    def test_fulfillment_validation(self, minimal_prefix):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_prefix.fulfillment)
        assert fulfillment.validate(minimal_prefix.message)

    def test_condition_validation(self, minimal_prefix):
        """

        1. Parse condition.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(minimal_prefix.condition_binary)
        assert condition.validate()

    def test_fulfillment_fingerprint_generation(self, minimal_prefix):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_prefix.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == minimal_prefix.fingerprint_contents

    def test_fulfillment_condition_generation(self, minimal_prefix):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_prefix.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == minimal_prefix.condition_uri

    def test_fulfillment_parsing_from_json(self, minimal_prefix):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(minimal_prefix.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == minimal_prefix.fulfillment


class TestMinimalThreshold:
    def test_condition_from_binary_to_serialize_uri(self, minimal_threshold):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        buffer_ = minimal_threshold.condition_binary
        condition = Condition.from_binary(buffer_)
        assert condition.serialize_uri() == minimal_threshold.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, minimal_threshold):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(minimal_threshold.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == minimal_threshold.condition_binary

    def test_fulfillment_parsing(self, minimal_threshold):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_threshold.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == minimal_threshold.fulfillment

    def test_fulfillment_validation(self, minimal_threshold):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_threshold.fulfillment)
        assert fulfillment.validate(minimal_threshold.message)

    def test_condition_validation(self, minimal_threshold):
        """

        1. Parse condition.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(minimal_threshold.condition_binary)
        assert condition.validate()

    def test_fulfillment_fingerprint_generation(self, minimal_threshold):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_threshold.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == minimal_threshold.fingerprint_contents

    def test_fulfillment_condition_generation(self, minimal_threshold):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_threshold.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == minimal_threshold.condition_uri

    def test_fulfillment_parsing_from_json(self, minimal_threshold):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(minimal_threshold.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == minimal_threshold.fulfillment


class TestMinimalRsa:
    def test_condition_from_binary_to_serialize_uri(self, minimal_rsa):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(minimal_rsa.condition_binary)
        assert condition.serialize_uri() == minimal_rsa.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, minimal_rsa):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(minimal_rsa.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == minimal_rsa.condition_binary

    def test_fulfillment_parsing(self, minimal_rsa):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_rsa.fulfillment)
        assert fulfillment.serialize_uri() == minimal_rsa.fulfillment

    def test_fulfillment_validation(self, minimal_rsa):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_rsa.fulfillment)
        assert fulfillment.validate(minimal_rsa.message)

    def test_condition_validation(self, minimal_rsa):
        """

        1. Parse condition.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(minimal_rsa.condition_binary)
        assert condition.validate()

    def test_fulfillment_fingerprint_generation(self, minimal_rsa):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_rsa.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == minimal_rsa.fingerprint_contents

    def test_fulfillment_condition_generation(self, minimal_rsa):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_rsa.fulfillment)
        condition = fulfillment.condition
        assert condition.serialize_uri() == minimal_rsa.condition_uri

    def test_fulfillment_parsing_from_json(self, minimal_rsa):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(minimal_rsa.json)
        assert fulfillment.serialize_uri() == minimal_rsa.fulfillment


class TestMinimalEd25519:
    def test_condition_from_binary_to_serialize_uri(self, minimal_ed25519):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(minimal_ed25519.condition_binary)
        assert condition.serialize_uri() == minimal_ed25519.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, minimal_ed25519):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(minimal_ed25519.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == minimal_ed25519.condition_binary

    def test_fulfillment_parsing(self, minimal_ed25519):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_ed25519.fulfillment)
        generated_fulfillment_uri = fulfillment.serialize_uri()
        assert generated_fulfillment_uri == minimal_ed25519.fulfillment

    def test_fulfillment_validation(self, minimal_ed25519):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_ed25519.fulfillment)
        assert fulfillment.validate(message=minimal_ed25519.message)

    def test_condition_validation(self, minimal_ed25519):
        """

        1. Parse condition.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(minimal_ed25519.condition_binary)
        assert condition.validate()

    def test_fulfillment_fingerprint_generation(self, minimal_ed25519):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_ed25519.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == minimal_ed25519.fingerprint_contents

    def test_fulfillment_condition_generation(self, minimal_ed25519):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(minimal_ed25519.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == minimal_ed25519.condition_uri

    def test_fulfillment_parsing_from_json(self, minimal_ed25519):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(minimal_ed25519.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == minimal_ed25519.fulfillment

    def test_signature_generation(self, minimal_ed25519):
        """Given a test vectors containing:

            * a public key,
            * a message, and
            * a signature

        generate the correct signature using the public key and message.

        """
        from cryptoconditions.types.ed25519 import Ed25519Sha256
        from cryptoconditions.crypto import base64_add_padding

        fulfillment = Ed25519Sha256(
            public_key=urlsafe_b64decode(base64_add_padding(minimal_ed25519.json["publicKey"]))
        )
        signature = fulfillment.sign(
            message=minimal_ed25519.message,
            private_key=minimal_ed25519.private_key,
        )
        assert signature == urlsafe_b64decode(base64_add_padding(minimal_ed25519.json["signature"]))


###############################################################################
#                                                                             #
#                           Basic cases                                       #
#                                                                             #
###############################################################################
class TestBasicPreimage:
    def test_condition_from_binary_to_serialize_uri(self, basic_preimage):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        buffer_ = basic_preimage.condition_binary
        condition = Condition.from_binary(buffer_)
        assert condition.serialize_uri() == basic_preimage.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_preimage):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_preimage.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_preimage.condition_binary

    def test_fulfillment_parsing(self, basic_preimage):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_preimage.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_preimage.fulfillment

    def test_fulfillment_validation(self, basic_preimage):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_preimage.fulfillment)
        assert fulfillment.validate(basic_preimage.message)

    def test_fulfillment_fingerprint_generation(self, basic_preimage):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_preimage.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_preimage.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_preimage):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_preimage.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_preimage.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_preimage):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_preimage.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_preimage.fulfillment


class TestBasicPrefix:
    def test_condition_from_binary_to_serialize_uri(self, basic_prefix):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_prefix.condition_binary)
        assert condition.serialize_uri() == basic_prefix.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_prefix):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_prefix.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_prefix.condition_binary

    def test_fulfillment_parsing(self, basic_prefix):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_prefix.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_prefix.fulfillment

    def test_fulfillment_validation(self, basic_prefix):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_prefix.fulfillment)
        assert fulfillment.validate(basic_prefix.message)

    def test_fulfillment_fingerprint_generation(self, basic_prefix):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_prefix.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_prefix.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_prefix):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_prefix.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_prefix.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_prefix):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_prefix.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_prefix.fulfillment


class TestBasicPrefixTwoLevelsDeep:
    def test_condition_from_binary_to_serialize_uri(self, basic_prefix_two_levels_deep):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_prefix_two_levels_deep.condition_binary)
        assert condition.serialize_uri() == basic_prefix_two_levels_deep.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_prefix_two_levels_deep):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_prefix_two_levels_deep.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_prefix_two_levels_deep.condition_binary

    def test_fulfillment_parsing(self, basic_prefix_two_levels_deep):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_prefix_two_levels_deep.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_prefix_two_levels_deep.fulfillment

    def test_fulfillment_validation(self, basic_prefix_two_levels_deep):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_prefix_two_levels_deep.fulfillment)
        assert fulfillment.validate(basic_prefix_two_levels_deep.message)

    def test_fulfillment_fingerprint_generation(self, basic_prefix_two_levels_deep):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_prefix_two_levels_deep.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_prefix_two_levels_deep.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_prefix_two_levels_deep):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_prefix_two_levels_deep.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_prefix_two_levels_deep.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_prefix_two_levels_deep):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_prefix_two_levels_deep.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_prefix_two_levels_deep.fulfillment


class TestBasicThreshold:
    def test_condition_from_binary_to_serialize_uri(self, basic_threshold):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_threshold.condition_binary)
        assert condition.serialize_uri() == basic_threshold.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_threshold):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_threshold.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_threshold.condition_binary

    def test_fulfillment_parsing(self, basic_threshold):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold.fulfillment

    def test_fulfillment_validation(self, basic_threshold):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold.fulfillment)
        assert fulfillment.validate(basic_threshold.message)

    def test_fulfillment_fingerprint_generation(self, basic_threshold):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_threshold.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_threshold):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_threshold.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_threshold):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_threshold.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold.fulfillment


class TestBasicThresholdSameConditionTwice:
    def test_condition_from_binary_to_serialize_uri(self, basic_threshold_same_condition_twice):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_threshold_same_condition_twice.condition_binary)
        assert condition.serialize_uri() == basic_threshold_same_condition_twice.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_threshold_same_condition_twice):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_threshold_same_condition_twice.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_threshold_same_condition_twice.condition_binary

    def test_fulfillment_parsing(self, basic_threshold_same_condition_twice):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_same_condition_twice.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold_same_condition_twice.fulfillment

    def test_fulfillment_validation(self, basic_threshold_same_condition_twice):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_same_condition_twice.fulfillment)
        assert fulfillment.validate(basic_threshold_same_condition_twice.message)

    def test_fulfillment_fingerprint_generation(self, basic_threshold_same_condition_twice):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_same_condition_twice.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_threshold_same_condition_twice.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_threshold_same_condition_twice):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_same_condition_twice.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_threshold_same_condition_twice.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_threshold_same_condition_twice):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_threshold_same_condition_twice.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold_same_condition_twice.fulfillment


class TestBasicThresholdSameFulfillmentTwice:
    def test_condition_from_binary_to_serialize_uri(self, basic_threshold_same_fulfillment_twice):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_threshold_same_fulfillment_twice.condition_binary)
        assert condition.serialize_uri() == basic_threshold_same_fulfillment_twice.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_threshold_same_fulfillment_twice):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_threshold_same_fulfillment_twice.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_threshold_same_fulfillment_twice.condition_binary

    def test_fulfillment_parsing(self, basic_threshold_same_fulfillment_twice):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_same_fulfillment_twice.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold_same_fulfillment_twice.fulfillment

    def test_fulfillment_validation(self, basic_threshold_same_fulfillment_twice):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_same_fulfillment_twice.fulfillment)
        assert fulfillment.validate(basic_threshold_same_fulfillment_twice.message)

    def test_fulfillment_fingerprint_generation(self, basic_threshold_same_fulfillment_twice):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_same_fulfillment_twice.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_threshold_same_fulfillment_twice.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_threshold_same_fulfillment_twice):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_same_fulfillment_twice.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_threshold_same_fulfillment_twice.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_threshold_same_fulfillment_twice):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_threshold_same_fulfillment_twice.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold_same_fulfillment_twice.fulfillment


class TestBasicThresholdTwoLevelsDeep:
    def test_condition_from_binary_to_serialize_uri(self, basic_threshold_two_levels_deep):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_threshold_two_levels_deep.condition_binary)
        assert condition.serialize_uri() == basic_threshold_two_levels_deep.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_threshold_two_levels_deep):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_threshold_two_levels_deep.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_threshold_two_levels_deep.condition_binary

    def test_fulfillment_parsing(self, basic_threshold_two_levels_deep):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_two_levels_deep.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold_two_levels_deep.fulfillment

    def test_fulfillment_validation(self, basic_threshold_two_levels_deep):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_two_levels_deep.fulfillment)
        assert fulfillment.validate(basic_threshold_two_levels_deep.message)

    def test_fulfillment_fingerprint_generation(self, basic_threshold_two_levels_deep):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_two_levels_deep.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_threshold_two_levels_deep.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_threshold_two_levels_deep):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_two_levels_deep.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_threshold_two_levels_deep.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_threshold_two_levels_deep):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_threshold_two_levels_deep.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold_two_levels_deep.fulfillment


class TestBasicThresholdSchroedinger:
    def test_condition_from_binary_to_serialize_uri(self, basic_threshold_schroedinger):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_threshold_schroedinger.condition_binary)
        assert condition.serialize_uri() == basic_threshold_schroedinger.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_threshold_schroedinger):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_threshold_schroedinger.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_threshold_schroedinger.condition_binary

    def test_fulfillment_parsing(self, basic_threshold_schroedinger):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_schroedinger.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold_schroedinger.fulfillment

    def test_fulfillment_validation(self, basic_threshold_schroedinger):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_schroedinger.fulfillment)
        assert fulfillment.validate(basic_threshold_schroedinger.message)

    def test_fulfillment_fingerprint_generation(self, basic_threshold_schroedinger):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_schroedinger.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_threshold_schroedinger.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_threshold_schroedinger):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_threshold_schroedinger.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_threshold_schroedinger.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_threshold_schroedinger):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_threshold_schroedinger.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_threshold_schroedinger.fulfillment


class TestBasicRsa:
    def test_condition_from_binary_to_serialize_uri(self, basic_rsa):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        buffer_ = basic_rsa.condition_binary
        condition = Condition.from_binary(buffer_)
        assert condition.serialize_uri() == basic_rsa.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_rsa):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_rsa.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_rsa.condition_binary

    def test_fulfillment_parsing(self, basic_rsa):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_rsa.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_rsa.fulfillment

    def test_fulfillment_validation(self, basic_rsa):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_rsa.fulfillment)
        assert fulfillment.validate(basic_rsa.message)

    def test_fulfillment_fingerprint_generation(self, basic_rsa):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_rsa.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_rsa.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_rsa):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_rsa.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_rsa.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_rsa):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_rsa.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_rsa.fulfillment


class TestBasicRsa4096:
    def test_condition_from_binary_to_serialize_uri(self, basic_rsa4096):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_rsa4096.condition_binary)
        assert condition.serialize_uri() == basic_rsa4096.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_rsa4096):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_rsa4096.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_rsa4096.condition_binary

    def test_fulfillment_parsing(self, basic_rsa4096):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_rsa4096.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_rsa4096.fulfillment

    def test_fulfillment_validation(self, basic_rsa4096):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_rsa4096.fulfillment)
        assert fulfillment.validate(basic_rsa4096.message)

    def test_fulfillment_fingerprint_generation(self, basic_rsa4096):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_rsa4096.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_rsa4096.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_rsa4096):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_rsa4096.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_rsa4096.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_rsa4096):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_rsa4096.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_rsa4096.fulfillment


class TestBasicEd25519:
    def test_condition_from_binary_to_serialize_uri(self, basic_ed25519):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(basic_ed25519.condition_binary)
        assert condition.serialize_uri() == basic_ed25519.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, basic_ed25519):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(basic_ed25519.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == basic_ed25519.condition_binary

    def test_fulfillment_parsing(self, basic_ed25519):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_ed25519.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_ed25519.fulfillment

    def test_fulfillment_validation(self, basic_ed25519):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_ed25519.fulfillment)
        assert fulfillment.validate(message=basic_ed25519.message)

    def test_fulfillment_fingerprint_generation(self, basic_ed25519):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_ed25519.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == basic_ed25519.fingerprint_contents

    def test_fulfillment_condition_generation(self, basic_ed25519):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(basic_ed25519.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == basic_ed25519.condition_uri

    def test_fulfillment_parsing_from_json(self, basic_ed25519):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(basic_ed25519.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == basic_ed25519.fulfillment

    def test_signature_generation(self, basic_ed25519):
        """Given a test vectors containing:

            * a public key,
            * a message, and
            * a signature

        generate the correct signature using the public key and message.

        """
        from cryptoconditions.types.ed25519 import Ed25519Sha256
        from cryptoconditions.crypto import base64_add_padding

        fulfillment = Ed25519Sha256(public_key=urlsafe_b64decode(base64_add_padding(basic_ed25519.json["publicKey"])))
        signature = fulfillment.sign(
            message=basic_ed25519.message,
            private_key=basic_ed25519.private_key,
        )
        assert signature == urlsafe_b64decode(base64_add_padding(basic_ed25519.json["signature"]))


###############################################################################
#                                                                             #
#                           Advanced cases                                    #
#                                                                             #
###############################################################################
class TestNotarizedReceipt:
    def test_condition_from_binary_to_serialize_uri(self, notarized_receipt):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(notarized_receipt.condition_binary)
        assert condition.serialize_uri() == notarized_receipt.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, notarized_receipt):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(notarized_receipt.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == notarized_receipt.condition_binary

    def test_fulfillment_parsing(self, notarized_receipt):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(notarized_receipt.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == notarized_receipt.fulfillment

    def test_fulfillment_validation(self, notarized_receipt):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(notarized_receipt.fulfillment)
        assert fulfillment.validate(notarized_receipt.message)

    def test_fulfillment_fingerprint_generation(self, notarized_receipt):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(notarized_receipt.fulfillment)
        fingerprint_contents = fulfillment.fingerprint_contents
        assert fingerprint_contents == notarized_receipt.fingerprint_contents

    def test_fulfillment_condition_generation(self, notarized_receipt):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(notarized_receipt.fulfillment)
        condition = fulfillment.condition
        condition_uri = condition.serialize_uri()
        assert condition_uri == notarized_receipt.condition_uri

    def test_fulfillment_parsing_from_json(self, notarized_receipt):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(notarized_receipt.json)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == notarized_receipt.fulfillment


class TestNotarizedReceiptMultipleNotaries:
    def test_condition_from_binary_to_serialize_uri(self, notarized_receipt_multiple_notaries):
        """

        1. Parse condition_binary.
        2. Serialize as a URI.
        3. Should match condition_uri.

        """
        from cryptoconditions import Condition

        condition = Condition.from_binary(notarized_receipt_multiple_notaries.condition_binary)
        assert condition.serialize_uri() == notarized_receipt_multiple_notaries.condition_uri

    def test_condition_from_uri_to_serialize_binary(self, notarized_receipt_multiple_notaries):
        """

        1. Parse condition_uri.
        2. serialize as binary.
        3. should match condition_binary.

        """
        from cryptoconditions import Condition

        condition = Condition.from_uri(notarized_receipt_multiple_notaries.condition_uri)
        generated_condition_binary = condition.serialize_binary()
        assert generated_condition_binary == notarized_receipt_multiple_notaries.condition_binary

    def test_fulfillment_parsing(self, notarized_receipt_multiple_notaries):
        """

        1. Parse fulfillment.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(notarized_receipt_multiple_notaries.fulfillment)
        fulfillment_uri = fulfillment.serialize_uri()
        assert fulfillment_uri == notarized_receipt_multiple_notaries.fulfillment

    def test_fulfillment_validation(self, notarized_receipt_multiple_notaries):
        """

        1. Parse fulfillment.
        2. Validate.
        3. Should return True.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(notarized_receipt_multiple_notaries.fulfillment)
        assert fulfillment.validate(notarized_receipt_multiple_notaries.message)

    def test_fulfillment_fingerprint_generation(self, notarized_receipt_multiple_notaries):
        """

        1. Parse fulfillment.
        2. Generate the fingerprint contents.
        3, Should match fingerprint_contents.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(notarized_receipt_multiple_notaries.fulfillment)
        assert fulfillment.fingerprint_contents == notarized_receipt_multiple_notaries.fingerprint_contents

    def test_fulfillment_condition_generation(self, notarized_receipt_multiple_notaries):
        """

        1. Parse fulfillment.
        2. Generate the condition.
        3. Serialize the condition as a URI.
        4. Should match conditionUri.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_uri(notarized_receipt_multiple_notaries.fulfillment)
        condition = fulfillment.condition
        assert condition.serialize_uri() == notarized_receipt_multiple_notaries.condition_uri

    def test_fulfillment_parsing_from_json(self, notarized_receipt_multiple_notaries):
        """

        1. Create fulfillment from json.
        2. Serialize fulfillment.
        3. Should match fulfillment.

        """
        from cryptoconditions import Fulfillment

        fulfillment = Fulfillment.from_json(notarized_receipt_multiple_notaries.json)
        assert fulfillment.serialize_uri() == notarized_receipt_multiple_notaries.fulfillment
