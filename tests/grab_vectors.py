#!/usr/bin/env python
""" .. todo:: docs """
import json
from urllib.request import urlopen


vectors_base_url = "https://raw.githubusercontent.com/rfcs/" "crypto-conditions/master/test-vectors/valid/"

vector_names = (
    "0000_test-minimal-preimage",
    "0001_test-minimal-prefix",
    "0002_test-minimal-threshold",
    "0003_test-minimal-rsa",
    "0004_test-minimal-ed25519",
    "0005_test-basic-preimage",
    "0006_test-basic-prefix",
    "0007_test-basic-prefix-two-levels-deep",
    "0008_test-basic-threshold",
    "0009_test-basic-threshold-same-condition-twice",
    "0010_test-basic-threshold-same-fulfillment-twice",
    "0011_test-basic-threshold-two-levels-deep",
    "0012_test-basic-threshold-schroedinger",
    "0013_test-basic-rsa",
    "0014_test-basic-rsa4096",
    "0015_test-basic-ed25519",
    "0016_test-advanced-notarized-receipt",
    "0017_test-advanced-notarized-receipt-multiple-notaries",
)


def download_vectors(vectors_base_url=vectors_base_url, vector_names=vector_names):
    """.. todo:: docs"""
    for vector_name in vector_names:
        print("Downloading test vector: {}".format(vector_name))
        vector_data = json.loads(urlopen("{}{}.json".format(vectors_base_url, vector_name)).read().decode())
        vector_filename = "tests/vectors/{}.json".format(vector_name)
        with open(vector_filename, "w") as json_file:
            json.dump(vector_data, json_file, indent=4)


if __name__ == "__main__":
    download_vectors()
