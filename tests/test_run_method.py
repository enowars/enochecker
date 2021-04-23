#!/usr/bin/env python3
import socket
import sys
import tempfile
from itertools import product
from logging import DEBUG

import pytest
import requests
from enochecker import BaseChecker, BrokenServiceException, OfflineException
from enochecker.results import CheckerResult
from enochecker_core import CheckerMethod, CheckerTaskMessage, CheckerTaskResult


@pytest.fixture()
def checker_cls():
    class CheckerExampleImpl(BaseChecker):
        port = 9999
        flag_variants = 1
        noise_variants = 1
        havoc_variants = 1

        def __init__(
            self, method=CheckerMethod.CHECKER_METHOD_PUTFLAG, **kwargs,
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
                    flag="testflag",
                    variant_id=0,
                    timeout=30000,
                    round_length=60000,
                    task_chain_id="test",
                )
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


@pytest.mark.parametrize("method", list(CheckerMethod))
def test_run_return_nothing(method, checker_cls):
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult.CHECKER_TASK_RESULT_OK


@pytest.mark.parametrize(
    "method, result", product(list(CheckerMethod), list(CheckerTaskResult))
)
def test_run_return_status(method, result, checker_cls):
    def meth(self):
        return result

    setattr(checker_cls, str(method), meth)
    c = checker_cls(method)
    with pytest.deprecated_call():
        res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult(result)


@pytest.mark.parametrize("method", list(CheckerMethod))
def test_raise_broken_service_exception(method, checker_cls):
    def meth(self):
        raise BrokenServiceException("msg123")

    setattr(checker_cls, str(method), meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult.CHECKER_TASK_RESULT_MUMBLE
    assert res.message == "msg123"


@pytest.mark.parametrize("method", list(CheckerMethod))
def test_raise_offline_exception(method, checker_cls):
    def meth(self):
        raise OfflineException("msg123")

    setattr(checker_cls, str(method), meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult.CHECKER_TASK_RESULT_OFFLINE
    assert res.message == "msg123"


@pytest.mark.parametrize("method", list(CheckerMethod))
def test_raise_unhandled_exception(method, checker_cls):
    def meth(self):
        raise Exception("msg123")

    setattr(checker_cls, str(method), meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR
    assert (
        not res.message
    )  # make sure no checker internals are leaked to the scoreboard


@pytest.mark.parametrize("method", list(CheckerMethod))
def test_invalid_return(method, checker_cls):
    def meth(self):
        return "lolthisisinvalid"

    setattr(checker_cls, str(method), meth)
    c = checker_cls(method)
    with pytest.deprecated_call():
        res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR
    assert (
        not res.message
    )  # make sure no checker internals are leaked to the scoreboard


def test_run_invalid_method(checker_cls):
    c = checker_cls()
    res = c.run("lolthisisinvalid")
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult.CHECKER_TASK_RESULT_INTERNAL_ERROR


@pytest.mark.parametrize(
    "method, exc", product(list(CheckerMethod), [requests.HTTPError, EOFError])
)
def test_requests_mumble(method, exc, checker_cls):
    def meth(self):
        raise exc()

    setattr(checker_cls, str(method), meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult.CHECKER_TASK_RESULT_MUMBLE
    assert res.message


@pytest.mark.parametrize(
    "method, exc",
    product(
        list(CheckerMethod),
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

    setattr(checker_cls, str(method), meth)
    c = checker_cls(method)
    res = c.run()
    assert isinstance(res, CheckerResult)
    assert res.result == CheckerTaskResult.CHECKER_TASK_RESULT_OFFLINE
    assert res.message


def main():
    pytest.main(sys.argv)


if __name__ == "__main__":
    main()
