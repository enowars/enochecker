from enochecker import BrokenServiceException
from enochecker.utils import (
    assert_equals,
    assert_in,
    base64ify,
    debase64ify,
    ensure_bytes,
    ensure_unicode,
    ensure_valid_filename,
    sha256ify,
    snake_caseify,
)

import pytest


def test_assert_in():
    with pytest.raises(BrokenServiceException) as ex:
        assert_in("a", "b", "test_message")
    assert str(ex.value) == "test_message"

    with pytest.raises(BrokenServiceException):
        assert_in("a", None)

    assert_in("a", "aa")

    with pytest.raises(BrokenServiceException):
        assert_in("a", "b")


def test_assert_equals():
    with pytest.raises(BrokenServiceException) as ex:
        assert_equals("a", "b", "test_message")
    assert str(ex.value) == "test_message"

    # no autobyteify
    with pytest.raises(BrokenServiceException):
        assert_equals("a", b"a")
    with pytest.raises(BrokenServiceException):
        assert_equals(b"a", "a")
    assert_equals("a", "a")
    assert_equals(b"a", b"a")

    # with autobyteify
    assert_equals("a", b"a", autobyteify=True)
    assert_equals(b"a", "a", autobyteify=True)
    assert_equals("a", "a", autobyteify=True)
    assert_equals(b"a", b"a", autobyteify=True)


def test_ensure_bytes():
    with pytest.raises(ValueError):
        ensure_bytes(None)

    assert ensure_bytes(b"a") == b"a"
    assert ensure_bytes("a") == b"a"
    assert ensure_bytes(1) == b"1"


def test_ensure_unicode():
    with pytest.raises(ValueError):
        ensure_unicode(None)

    assert ensure_unicode(b"a") == "a"
    assert ensure_unicode("a") == "a"
    assert ensure_unicode(1) == "1"


def test_ensure_valid_filename():
    assert ensure_valid_filename("filename") == "filename"
    assert " " not in ensure_valid_filename("file name")
    assert "/" not in ensure_valid_filename("file/name")
    assert "/" not in ensure_valid_filename("../filename")
    assert "\\" not in ensure_valid_filename("file\\name")

    # ensure the function is deterministic
    assert ensure_valid_filename("./\\..filename") == ensure_valid_filename(
        "./\\..filename"
    )
    assert ensure_valid_filename("./\\..filename", 100) == ensure_valid_filename(
        "./\\..filename", 100
    )

    # ensure reaching min_length does not introduce special characters
    assert " " not in ensure_valid_filename("file name", 100)
    assert "/" not in ensure_valid_filename("file/name", 100)
    assert "/" not in ensure_valid_filename("../filename", 100)
    assert "\\" not in ensure_valid_filename("file\\name", 100)

    assert len(ensure_valid_filename("")) >= 3
    assert len(ensure_valid_filename("", 10)) >= 10


def test_snake_caseify():
    assert snake_caseify("Lol") == "lol"
    assert snake_caseify("lol") == "lol"

    assert snake_caseify("LolTest") == "lol_test"
    assert snake_caseify("lolTest") == "lol_test"

    assert snake_caseify("LolTestWorks") == "lol_test_works"
    assert snake_caseify("lolTestWorks") == "lol_test_works"


def test_sha256ify():
    assert (
        sha256ify("test")
        == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    )
    assert (
        sha256ify(b"test")
        == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    )


def test_base64ify():
    assert base64ify(b"test") == "dGVzdA=="
    assert base64ify("test") == "dGVzdA=="

    assert base64ify(b"\xfftes\xee") == "/3Rlc+4="
    assert base64ify(b"\xfftes\xee", "_-") == "-3Rlc_4="
    assert base64ify(b"\xfftes\xee", "-_") == "_3Rlc-4="


def test_debase64ify():
    assert debase64ify(b"dGVzdA==") == "test"
    assert debase64ify("dGVzdA==") == "test"

    assert debase64ify("8J+dgQ==") == b"\xf0\x9f\x9d\x81".decode()
    assert debase64ify("MdW/") == b"\x31\xd5\xbf".decode()
    assert debase64ify("8J-dgQ==", "-_") == b"\xf0\x9f\x9d\x81".decode()
    assert debase64ify("MdW_", "-_") == b"\x31\xd5\xbf".decode()
    assert debase64ify("8J_dgQ==", "_-") == b"\xf0\x9f\x9d\x81".decode()
    assert debase64ify("MdW-", "_-") == b"\x31\xd5\xbf".decode()
