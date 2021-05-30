import secrets

import pytest

from enochecker.nosqldict import NoSqlDict


@pytest.fixture
def nosqldict():
    dict_name = secrets.token_hex(8)
    checker_name = secrets.token_hex(8)
    return NoSqlDict(dict_name, checker_name)


@pytest.mark.nosqldict
def test_basic(nosqldict):
    nosqldict["abc"] = "xyz"
    assert nosqldict["abc"] == "xyz"

    with pytest.raises(KeyError):
        _ = nosqldict["xyz"]

    nosqldict["abc"] = {"stuff": b"asd"}
    assert nosqldict["abc"] == {"stuff": b"asd"}

    del nosqldict["abc"]
    with pytest.raises(KeyError):
        _ = nosqldict["abc"]


@pytest.mark.nosqldict
def test_nested_change():
    dict_name = secrets.token_hex(8)
    checker_name = secrets.token_hex(8)

    def scoped_access(dict_name, checker_name):
        nosqldict = NoSqlDict(dict_name, checker_name)

        x = {
            "asd": 123,
        }
        nosqldict["test"] = x
        x["asd"] = 456

        assert nosqldict["test"] == {
            "asd": 456,
        }

    scoped_access(dict_name, checker_name)

    nosqldict_new = NoSqlDict(dict_name, checker_name)

    assert nosqldict_new["test"] == {
        "asd": 456,
    }
