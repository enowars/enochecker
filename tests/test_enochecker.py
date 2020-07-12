#!/usr/bin/env python3
import functools
import sys
import tempfile
import time
from logging import DEBUG

import enochecker
import pytest

from enochecker import (
    CHECKER_METHODS,
    BaseChecker,
    BrokenServiceException,
    OfflineException,
    Result,
    assert_equals,
    assert_in,
    ensure_bytes,
    ensure_unicode,
    parse_args,
    readline_expect,
    run,
    serve_once,
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
    flag_count = 1
    noise_count = 1
    havoc_count = 1

    def __init__(
        self,
        method=CHECKER_METHODS[0],
        run_id=0,
        address="localhost",
        team_name="Testteam",
        team_id=1,
        flag_round=None,
        round_length=300,
        flag_idx=None,
        storage_dir=None,
        log_endpoint=None,
        use_db_cache=True,
        json_logging=True,
        round_id=1,
        flag="ENOFLAG",
        timeout=30000,
        **kwargs,
    ):
        """
        An mocked implementation of a checker for testing purposes
        :param method: The method the checker uses
        :param fail: If and how
        """
        super(CheckerExampleImpl, self).__init__(
            method=method,
            run_id=run_id,
            address=address,
            team_name=team_name,
            team_id=team_id,
            flag_round=flag_round,
            round_length=round_length,
            flag_idx=flag_idx,
            storage_dir=storage_dir or STORAGE_DIR,
            use_db_cache=use_db_cache,
            json_logging=json_logging,
            round_id=round_id,
            flag=flag,
            timeout=timeout,
            **kwargs,
        )
        self.logger.setLevel(DEBUG)

    def putflag(self):
        self.team_db["flag"] = self.flag
        if self.flag_idx == 2:
            self.info("RAN IDX 2")
            raise Exception()

    def getflag(self):
        try:
            if not self.team_db["flag"] == self.flag:
                raise BrokenServiceException("Flag not found!")
        except KeyError:
            raise BrokenServiceException("Flag not correct!")

    def putnoise(self):
        self.team_db["noise"] = self.noise

    def getnoise(self):
        try:
            if not self.team_db["noise"] == self.noise:
                raise BrokenServiceException("Noise not correct!")
        except KeyError:
            raise BrokenServiceException("Noise not found!")

    def havoc(self):
        raise OfflineException(
            "Could not connect to team {} at {}:{} because this is not a real checker script.".format(
                self.team, self.address, self.port
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


def test_args():
    with pytest.raises(SystemExit):
        parse_args()

    argv = [
        "run",
        CHECKER_METHODS[0],
        "-a",
        "localhost",
        "-t",
        "TestTeam",
        "-I",
        "1",
        "-f",
        "ENOTESTFLAG",
        "-x",
        "30",
        "-i",
        "0",
        "-R",
        "500",
        "-F",
        "299",
        "-T",
        "19"
        # "-p", "1337"
    ]
    args = parse_args(argv)

    assert args.method == argv[1]
    assert args.address == argv[3]
    assert args.team_name == argv[5]
    assert args.round_id == int(argv[7])
    assert args.flag == argv[9]
    assert args.timeout == int(argv[11])
    assert args.flag_idx == int(argv[13])
    assert args.round_length == int(argv[15])
    assert args.flag_round == int(argv[17])
    assert args.team_id == int(argv[19])

    # assert args.port == int(argv[15])
    # port should be specified in the basechecker as a constant, so this test isn't neccesary


@temp_storage_dir
def test_checker_connections():
    # TODO: Check timeouts?
    text = "ECHO :)"
    _ = serve_once(text, 9999)
    checker = CheckerExampleImpl(
        CHECKER_METHODS[0],
    )  # Conflict between logging and enochecker.logging because of wildcart import
    assert (
        checker.http_get("/").text == text
    )  # Should probably rename it to enologger to avoid further conflicts

    # Give server time to shut down
    time.sleep(0.2)

    _ = serve_once(text, 9999)
    checker = CheckerExampleImpl(CHECKER_METHODS[0])
    t = checker.connect()
    t.write(b"GET / HTTP/1.0\r\n\r\n")
    assert readline_expect(t, "HTTP")
    t.close()


@temp_storage_dir
def test_checker():
    flag = "ENOFLAG"
    noise = "buzzzz! :)"

    CheckerExampleImpl(method="putflag").run()

    assert CheckerExampleImpl().team_db["flag"] == flag
    CheckerExampleImpl(method="getflag", flag=flag).run()

    CheckerExampleImpl(method="putnoise", flag=noise).run()
    assert CheckerExampleImpl().team_db["noise"] == noise
    CheckerExampleImpl(method="getnoise", flag=noise).run()

    assert CheckerExampleImpl(method="havoc").run().result == Result.OFFLINE


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


@temp_storage_dir
def test_exceptionHandling(capsys):
    # CheckerExampleImpl(method="putflag", call_idx=2).run()
    run(CheckerExampleImpl, args=["run", "putflag", "-i", "2"])

    a = capsys.readouterr()
    with capsys.disabled():
        print(a.out)


def main():
    pytest.main(sys.argv)


if __name__ == "__main__":
    main()
