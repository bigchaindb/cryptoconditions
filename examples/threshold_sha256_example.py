
import cryptoconditions as cc


threshold_fulfillment = cc.ThresholdSha256Fulfillment()
threshold_fulfillment.add_subcondition_uri('cc:4:20:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r8:96')
threshold_fulfillment.add_subfulfillment_uri('cf:0:')
threshold_fulfillment.threshold = 1  # defaults to subconditions.length
print(threshold_fulfillment.condition_uri)

threshold_fulfillment = cc.ThresholdSha256Fulfillment()
threshold_fulfillment.add_subfulfillment_uri('cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK')
threshold_fulfillment.add_subfulfillment_uri('cf:0:')
threshold_fulfillment.threshold = 1
print(threshold_fulfillment.condition_uri)
threshold_fulfillment_uri = threshold_fulfillment.serialize_uri()
print(threshold_fulfillment_uri)
subconditions = threshold_fulfillment.get_subcondition_from_vk('Gtbi6WQDB6wUePiZm8aYs5XZ5pUqx9jMMLvRVHPESTjU')
print(subconditions[0].serialize_uri())

threshold_fulfillment_uri = 'cf:2:AQEBAgEBAwAAAAABAQAnAAQBICDsFyuTrV5WO_STLHDhJFA0w1Rn7y79TWTr-BloNGfivwFg'
reparsed_fulfillment = cc.Fulfillment.from_uri(threshold_fulfillment_uri)
print(reparsed_fulfillment.serialize_uri())