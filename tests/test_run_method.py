import socket
import tempfile
from itertools import product
from logging import DEBUG

import pytest
import requests

from enochecker import (
    CHECKER_METHODS,
    BaseChecker,
    BrokenServiceException,
    OfflineException,
)
from enochecker.results import CheckerResult, Result

RESULTS = [Result.OK, Result.MUMBLE, Result.OFFLINE, Result.INTERNAL_ERROR]


@pytest.fixture()
def checker_cls():
    class CheckerExampleImpl(BaseChecker):
        port = 9999
        flag_count = 1
        noise_count = 1
        havoc_count = 1

        def __init__(
            self,
            method=CHECKER_METHODS[0],
            **kwargs,
        ):
            """
            An mocked implementation of a checker for testing purposes
            :param method: The method the checker uses
            :param fail: If and how
            """
            super(CheckerExampleImpl, self).__init__(
                method=method,
                run_id=0,
                address="localhost",
                team_name="Testteam",
                team_id=1,
                flag_round=1,
                round_length=300,
                flag_idx=0,
                storage_dir=CheckerExampleImpl._storage_dir,  # type: ignore
                use_db_cache=False,
                json_logging=True,
                round_id=1,
                flag="ENOFLAG",
                timeout=30000,
                **kwargs,
            )
            self.logger.setLevel(DEBUG)

        def putflag(self):
            pass

        def getflag(self):
            pass

        def putnoise(self):
            pass

        def getnoise(self):
            pass

        def havoc(self):
            pass

        def exploit(self):
            pass

    with tempfile.TemporaryDirectory() as tmpdirname:
        CheckerExampleImpl._storage_dir = tmpdirname  # type: ignore
        yield CheckerExampleImpl


@pytest.mark.parametrize("method", CHECKER_METHODS)
def test_run_return_nothing(method, checker_cls):
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == Result.OK


@pytest.mark.parametrize("method, result", product(CHECKER_METHODS, RESULTS))
def test_run_return_status(method, result, checker_cls):
    def meth(self):
        return result

    setattr(checker_cls, method, meth)
    c = checker_cls(method)
    with pytest.deprecated_call():
        res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == result


@pytest.mark.parametrize("method", CHECKER_METHODS)
def test_raise_broken_service_exception(method, checker_cls):
    def meth(self):
        raise BrokenServiceException("msg123")

    setattr(checker_cls, method, meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == Result.MUMBLE
    assert res.message == "msg123"


@pytest.mark.parametrize("method", CHECKER_METHODS)
def test_raise_offline_exception(method, checker_cls):
    def meth(self):
        raise OfflineException("msg123")

    setattr(checker_cls, method, meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == Result.OFFLINE
    assert res.message == "msg123"


@pytest.mark.parametrize("method", CHECKER_METHODS)
def test_raise_unhandled_exception(method, checker_cls):
    def meth(self):
        raise Exception("msg123")

    setattr(checker_cls, method, meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == Result.INTERNAL_ERROR
    assert (
        not res.message
    )  # make sure no checker internals are leaked to the scoreboard


@pytest.mark.parametrize("method", CHECKER_METHODS)
def test_invalid_return(method, checker_cls):
    def meth(self):
        return "lolthisisinvalid"

    setattr(checker_cls, method, meth)
    c = checker_cls(method)
    with pytest.deprecated_call():
        res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == Result.INTERNAL_ERROR
    assert (
        not res.message
    )  # make sure no checker internals are leaked to the scoreboard


def test_run_invalid_method(checker_cls):
    c = checker_cls()
    res = c.run("lolthisisinvalid")
    assert isinstance(res, CheckerResult)
    assert res.result == Result.INTERNAL_ERROR


@pytest.mark.parametrize(
    "method, exc", product(CHECKER_METHODS, [requests.HTTPError, EOFError])
)
def test_requests_mumble(method, exc, checker_cls):
    def meth(self):
        raise exc()

    setattr(checker_cls, method, meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == Result.MUMBLE
    assert res.message


@pytest.mark.parametrize(
    "method, exc",
    product(
        CHECKER_METHODS,
        [
            requests.ConnectionError,
            requests.exceptions.ConnectTimeout,
            TimeoutError,
            socket.timeout,
            ConnectionError,
            OSError,
            ConnectionAbortedError,
        ],
    ),
)
def test_offline_exceptions(method, exc, checker_cls):
    def meth(self):
        raise exc()

    setattr(checker_cls, method, meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == Result.OFFLINE
    assert res.message
