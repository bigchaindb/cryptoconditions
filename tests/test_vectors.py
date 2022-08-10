import json
from urllib.request import urlopen

import pytest

from .grab_vectors import vector_names


@pytest.mark.parametrize("vector_name", vector_names)
def test_local_json_vectors_synced_with_upstream(vector_name):
    from .grab_vectors import vectors_base_url

    vector_filename = "{}.json".format(vector_name)
    with open("tests/vectors/{}".format(vector_filename), "r") as jf:
        local_vector = json.load(jf)
    assert local_vector == json.loads(urlopen("{}{}".format(vectors_base_url, vector_filename)).read().decode())
