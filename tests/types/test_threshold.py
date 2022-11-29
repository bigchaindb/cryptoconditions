from pytest import mark, raises


class TestThresholdSha256:
    @mark.parametrize("threshold", (0, 0.1, "a"))
    def test_init_with_invalid_threshold(self, threshold):
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        with raises(ValueError) as exc:
            ThresholdSha256(threshold=threshold)
        assert exc.value.args == ("Threshold must be a integer greater than zero, was: {}".format(threshold),)

    def test_add_subcondition_type_error(self):
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        threshold_obj = ThresholdSha256()
        with raises(TypeError) as exc:
            threshold_obj.add_subcondition(123)
        assert exc.value.args == ("Subconditions must be URIs or objects of type Condition",)

    def test_add_subcondition_as_uri(self, minimal_threshold):
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256
        from planetmint_cryptoconditions.fulfillment import Fulfillment

        threshold_obj = ThresholdSha256(threshold=minimal_threshold.json["threshold"])
        subfulfillment = Fulfillment.from_json(minimal_threshold.json["subfulfillments"][0])
        subcondition_uri = subfulfillment.condition_uri
        threshold_obj.add_subcondition(subcondition_uri)
        threshold_obj.serialize_uri == minimal_threshold.fulfillment

    def test_add_subcondition_as_object(self, minimal_threshold):
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256
        from planetmint_cryptoconditions.fulfillment import Fulfillment

        threshold_obj = ThresholdSha256(threshold=minimal_threshold.json["threshold"])
        subfulfillment = Fulfillment.from_json(minimal_threshold.json["subfulfillments"][0])
        subcondition_object = subfulfillment.condition
        threshold_obj.add_subcondition(subcondition_object)
        threshold_obj.serialize_uri == minimal_threshold.fulfillment

    def test_add_subfulfillment_type_error(self):
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        threshold_obj = ThresholdSha256()
        with raises(TypeError) as exc:
            threshold_obj.add_subfulfillment(123)
        assert exc.value.args == ("Subfulfillments must be URIs or objects of type Fulfillment",)

    def test_add_subfulfillment_as_uri(self, minimal_threshold):
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256
        from planetmint_cryptoconditions.fulfillment import Fulfillment

        threshold_obj = ThresholdSha256(threshold=minimal_threshold.json["threshold"])
        subfulfillment = Fulfillment.from_json(minimal_threshold.json["subfulfillments"][0])
        subfulfillment_uri = subfulfillment.serialize_uri()
        threshold_obj.add_subfulfillment(subfulfillment_uri)
        threshold_obj.serialize_uri == minimal_threshold.fulfillment

    def test_add_subfulfillment_as_object(self, minimal_threshold):
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256
        from planetmint_cryptoconditions.fulfillment import Fulfillment

        threshold_obj = ThresholdSha256(threshold=minimal_threshold.json["threshold"])
        subfulfillment_object = Fulfillment.from_json(minimal_threshold.json["subfulfillments"][0])
        threshold_obj.add_subfulfillment(subfulfillment_object)
        threshold_obj.serialize_uri == minimal_threshold.fulfillment

    def test_asn1_dict_payload(self):
        from planetmint_cryptoconditions.exceptions import ValidationError
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        threshold_obj = ThresholdSha256(threshold=1)
        with raises(ValidationError) as exc:
            threshold_obj.asn1_dict_payload
        assert exc.value.args == ("Not enough fulfillments",)

    def test_calculate_worst_case_length(self):
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        cost = ThresholdSha256.calculate_worst_case_length(1, ())
        assert cost == float("-inf")

    def test_calculate_cost_missing_data_error(self):
        from planetmint_cryptoconditions.exceptions import MissingDataError
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        threshold_obj = ThresholdSha256(threshold=1)
        with raises(MissingDataError) as exc:
            threshold_obj.calculate_cost()
        assert exc.value.args == ("Insufficient number of subconditions to meet the threshold",)

    def test_validate_threshold_not_met(self):
        from planetmint_cryptoconditions.exceptions import ValidationError
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        threshold_obj = ThresholdSha256(threshold=1)
        with raises(ValidationError) as exc:
            threshold_obj.validate()
        assert exc.value.args == ("Threshold not met",)

    def test_validate_threshold_exceeded(self, basic_threshold):
        from planetmint_cryptoconditions.exceptions import ValidationError
        from planetmint_cryptoconditions.fulfillment import Fulfillment
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        threshold_obj = ThresholdSha256(threshold=2)
        for subfulfillment in basic_threshold.json["subfulfillments"]:
            threshold_obj.add_subfulfillment(Fulfillment.from_json(subfulfillment))
        with raises(ValidationError) as exc:
            threshold_obj.validate()
        assert exc.value.args == ("Fulfillment is not minimal",)

    def test_parse_json_with_subconditions(self, minimal_threshold):
        from planetmint_cryptoconditions.fulfillment import Fulfillment
        from planetmint_cryptoconditions.types.threshold import ThresholdSha256

        subfulfillment = Fulfillment.from_json(minimal_threshold.json.pop("subfulfillments")[0])
        subcondition_object = subfulfillment.condition
        minimal_threshold.json["subconditions"] = [subcondition_object.to_json()]
        threshold_obj = ThresholdSha256()
        threshold_obj.parse_json(minimal_threshold.json)
        assert len(threshold_obj.subconditions) == 1
        assert threshold_obj.subconditions[0]["body"].serialize_uri() == subfulfillment.condition_uri
