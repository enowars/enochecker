#!/usr/bin/env python3
import functools
import sys
import tempfile
from logging import DEBUG

import pytest
from enochecker_core import CheckerMethod, CheckerTaskMessage, CheckerTaskResult

import enochecker
from enochecker import (
    BaseChecker,
    BrokenServiceException,
    OfflineException,
    assert_equals,
    assert_in,
    ensure_bytes,
    ensure_unicode,
    snake_caseify,
)

STORAGE_DIR: str = "/tmp/enochecker_test"


def temp_storage_dir(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        global STORAGE_DIR
        try:
            with tempfile.TemporaryDirectory() as tmpdirname:
                STORAGE_DIR = tmpdirname
                return func(*args, **kwargs)
        finally:
            STORAGE_DIR = "/tmp/enochecker_test"

    return wrapper


class CheckerExampleImpl(BaseChecker):
    port = 9999
    flag_variants = 1
    noise_variants = 1
    havoc_variants = 1

    def __init__(
        self,
        method=CheckerMethod.CHECKER_METHOD_PUTFLAG,
        flag="ENOFLAG",
        task_chain_id="test",
        **kwargs,
    ):
        """
        An mocked implementation of a checker for testing purposes
        :param method: The method the checker uses
        :param fail: If and how
        """
        super(CheckerExampleImpl, self).__init__(
            CheckerTaskMessage(
                task_id=1,
                method=CheckerMethod(method),
                address="localhost",
                team_id=1,
                team_name="team1",
                current_round_id=1,
                related_round_id=1,
                flag=flag,
                variant_id=0,
                timeout=30000,
                round_length=60000,
                task_chain_id=task_chain_id,
            ),
            use_db_cache=False,
            **kwargs,
        )
        self.logger.setLevel(DEBUG)

    def putflag(self):
        self.chain_db = self.flag

    def getflag(self):
        try:
            if not self.chain_db == self.flag:
                raise BrokenServiceException("Flag not found!")
        except KeyError:
            raise BrokenServiceException("Flag not correct!")

    def putnoise(self):
        self.chain_db = self.flag

    def getnoise(self):
        try:
            if not self.chain_db == self.flag:
                raise BrokenServiceException("Noise not correct!")
        except KeyError:
            raise BrokenServiceException("Noise not found!")

    def havoc(self):
        raise OfflineException(
            "Could not connect to team {} at {}:{} because this is not a real checker script.".format(
                self.team_id, self.address, self.port
            )
        )

    def exploit(self):
        pass


def test_assert_equals():
    with pytest.raises(BrokenServiceException):
        assert_equals(1, 2)
    assert_equals(1, 1)
    assert_equals("test", b"test", autobyteify=True)
    if "test" == b"test":  # We ignore unicode stuff for python2...
        return
    with pytest.raises(BrokenServiceException) as ex:
        assert_equals("test", b"test", autobyteify=False, message="Fun")
    assert_equals(b"Fun", ex.value, autobyteify=True)


def test_conversions():
    assert isinstance(ensure_bytes("test"), bytes)
    assert isinstance(ensure_bytes(b"test"), bytes)
    assert isinstance(ensure_unicode("test"), type(""))
    assert isinstance(ensure_unicode(b"test"), type(""))
    assert ensure_unicode(ensure_bytes("test")) == "test"


def test_assert_in():
    with pytest.raises(BrokenServiceException):
        assert_in("fun", "games")
    assert_in("fun", "fun and games")
    assert_in("quack", ["quack", "foo"])


def test_snake_caseify():
    assert snake_caseify("ThisIsATest") == "this_is_a_test"


@temp_storage_dir
def test_dict():
    db = enochecker.storeddict.StoredDict(name="test", base_path=STORAGE_DIR)
    with pytest.raises(KeyError):
        _ = db["THIS_KEY_WONT_EXIST"]

    db["test"] = "test"
    assert not db.is_locked("fun")
    db.lock("fun")
    assert db.is_locked("fun")
    db["fun"] = "fun"
    db.release("fun")
    db["fun"] = "fun2"
    db.persist()

    db.reload()
    assert db["test"] == "test"

    db2 = enochecker.storeddict.StoredDict(name="test", base_path=STORAGE_DIR)
    assert db2["test"] == "test"

    assert len(db) > 0
    keys = [x for x in db.keys()]
    for key in keys:
        print(key)
        del db[key]
    db.persist()
    assert len(db) == 0


@temp_storage_dir
def test_checker():
    flag = "ENOFLAG"
    task_chain_id = "test_task_chain_id"

    CheckerExampleImpl(method="putflag").run()

    assert CheckerExampleImpl().chain_db == flag
    CheckerExampleImpl(method="getflag", flag=flag).run()

    CheckerExampleImpl(method="putnoise", task_chain_id=task_chain_id).run()
    assert CheckerExampleImpl(task_chain_id=task_chain_id).chain_db is not None
    CheckerExampleImpl(method="getnoise", task_chain_id=task_chain_id).run()

    assert (
        CheckerExampleImpl(method="havoc").run().result
        == CheckerTaskResult.CHECKER_TASK_RESULT_OFFLINE
    )


@temp_storage_dir
def test_useragents():
    flag = "ENOFLAG"
    checker = CheckerExampleImpl(method="putflag", flag=flag)
    first_agent = checker.http_useragent

    for _ in range(10):
        new_agent = checker.http_useragent_randomize()
        assert checker.http_useragent == new_agent
        if first_agent != checker.http_useragent:
            return

    assert first_agent != checker.http_useragent


def main():
    pytest.main(sys.argv)


if __name__ == "__main__":
    main()
