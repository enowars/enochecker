"""Collection of utilities for checker development."""

import base64
import hashlib
import logging
import re
import socket
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Match,
    Optional,
    Pattern,
    Sequence,
    Tuple,
    Union,
)

import pwnlib

from .results import BrokenServiceException, EnoException

PORT_MAX = 65535

logging.basicConfig(level=logging.DEBUG)
utilslogger = logging.Logger(__name__)
utilslogger.setLevel(logging.DEBUG)


def assert_in(o1: Any, o2: Any, message: Optional[str] = None) -> None:
    """
    Raise a BrokenServiceException if o1 not in o2.

    :param o1: the object that should be in o2
    :param o2: the object to look in
    :param message: An optional message that will be part of the error
    """
    if not o2 or o1 not in o2:
        raise BrokenServiceException(
            message or "Received unexpected response.",
            internal_message=f"{o1} is not in {o2}",
        )


def assert_equals(
    o1: Any, o2: Any, message: Optional[str] = None, autobyteify: bool = False
) -> None:
    """
    Raise a BrokenServiceException if o1 != o2.

    :param o1: the first object
    :param o2: the second object
    :param message: The exception message in case of an error (optional)
    :param autobyteify: will call ensure_bytes on both parameters.
    """
    if autobyteify:
        o1 = ensure_bytes(o1)
        o2 = ensure_bytes(o2)
    if o1 != o2:
        raise BrokenServiceException(
            message or "Received unexpected response.",
            internal_message=f"{o1} is not equal to {o2}",
        )


def assert_true(
    expression: Any, message: Optional[str] = None, autobyteify: bool = False
) -> None:
    """
    Raise a BrokenServiceException if expression is not True.

    :param o1: the element that should be True
    :param message: The exception message in case of an error (optional)
    :param autobyteify: will call ensure_bytes on both parameters.
    """
    assert_equals(expression, True, message, autobyteify)


def ensure_bytes(obj: Union[bytes, str, Any]) -> bytes:
    """
    Convert an object to bytes.

    If the input is bytes, the value remains unchanged.

    :param obj: str or bytes (or anything else) to convert to bytes representation
    :return: the bytes representation of the object
    """
    if obj is None:
        raise ValueError("Cannot byteify None")
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        return obj.encode("utf-8")
    return str(obj).encode("utf-8")


def ensure_valid_filename(s: str, min_length: int = 3) -> str:
    """
    Get a valid file name from the input.

    :param s: The input string
    :param min_length: if the result is smaller than this, the method will fall back to base64.
    :return: all illegal chars stripped or base64ified if it gets too small
    """
    s = str(s).strip().replace(" ", "_")
    s = re.sub(r"(?u)[^-\w.]", "", s)
    if not s:
        s = "_"
    while len(s) < min_length:
        s = base64ify(s, "+-")
    return s


def snake_caseify(camel: str) -> str:
    """
    Turn camels into snake (-cases).

    :param camel: camelOrSnakeWhatever
    :return: camel_or_snake_whatever
    """
    half_snake = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", camel)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", half_snake).lower()


def sha256ify(s: Union[str, bytes]) -> str:
    """
    Calculate the sha256 hash.

    Converts the input to bytes if it is a string.

    :param s: the string
    :return: the hash in hex representation
    """
    s = ensure_bytes(s)
    return hashlib.sha256(s).hexdigest()


def base64ify(s: Union[str, bytes], altchars: Union[str, bytes] = None) -> str:
    """
    Calculate the base64 representation of a value.

    :param s: the input string
    :param altchars: base64 encodes using the given altchars (or not, if None)
    :return: base64 representation
    """
    s = ensure_bytes(s)
    if altchars:
        altchars = ensure_bytes(altchars)
        return base64.b64encode(s, altchars).decode("utf-8")
    else:
        return base64.b64encode(s).decode("utf-8")


def debase64ify(
    s: Union[str, bytes], altchars: Optional[Union[str, bytes]] = None
) -> str:
    """
    Decode a base64-encoded string.

    :param s: the base64-encoded string
    :param altchars: base64 decodes using the given altchars (or not, if None)
    :return: the decoded value
    """
    s = ensure_bytes(s)
    if altchars:
        altchars = ensure_bytes(altchars)
        return base64.b64decode(s, altchars).decode("utf-8")
    else:
        return base64.b64decode(s).decode("utf-8")


class SimpleSocket(pwnlib.tubes.remote.remote):
    """
    Convenient socket wrapper using pwnlib's tubes.remote

    Read Pwnlib documentation for more info.
    """

    # pylint:  disable=protected-access
    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 0,
        timeout: float = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore
        logger: Optional[logging.Logger] = None,
        timeout_fun: Optional[Callable[[], float]] = None,
        *args: Tuple[Any, ...],
        **kwargs: Dict[str, Any],
    ) -> None:
        """
        Initialize a new SimpleSocket Object.

        :param host: the host to connect to
        :param port: the port to connect to
        :param timeout: The timeout passed in here counts for the whole session.
        :param logger: The optional logger to use
        :param timeout_fun: function that will output the current timeout on each call.
        """
        super().__init__(host, port, timeout=timeout, *args, **kwargs)
        self.socket: socket.socket = self.sock  # alias
        if logger:
            self.logger = logger
        else:
            self.logger = utilslogger
        self.timeout_fun: Optional[Callable[[], float]] = timeout_fun

    @property
    def current_default_timeout(self) -> float:
        """
        Get the timeout default that should currently be used.

        :return: current timeout default, either from self.timeout_fun or from timeout.
        """
        if self.timeout_fun:
            return self.timeout_fun()
        else:
            return self.timeout

    def readline_expect(
        self,
        expected: Union[str, bytes],
        read_until: Union[str, bytes] = b"\n",
        timeout: Optional[float] = None,
        exception_message: Optional[str] = None,
    ) -> bytes:
        """
        Read to newline (or read_until string) and assert the presence of a string in the response.

        Will raise an exception if failed.

        :param read_until: Which parameter to read until
        :param expected: the expected String to search for in the response
        :param timeout: The timeout (uses Telnet default if not passed in)
        :return read: the bytes read
        """
        if timeout is None:
            timeout = self.current_default_timeout

        expected = ensure_bytes(expected)
        read_until = ensure_bytes(read_until)

        read = self.read_until(read_until, timeout)
        if read == b"":
            err = "Expected {!r} but got nothing/timeout!".format(expected)
            self.logger.error(err, stack_info=True)
            self.close()
            if exception_message:
                raise BrokenServiceException(exception_message)
            else:
                raise BrokenServiceException("Service returned nothing (timeout?).")

        if expected not in read:
            err = "Expected {!r} but got {!r}".format(expected, read)
            self.logger.error(err, stack_info=True)
            self.close()
            if exception_message:
                raise BrokenServiceException(exception_message)
            else:
                raise BrokenServiceException("Service returned unexpected response.")
        return read

    def expect(
        self,
        regexes: Sequence[Union[Pattern[bytes], bytes, str]],
        timeout: Optional[float] = None,
    ) -> Tuple[int, Optional[Match[bytes]], bytes]:
        """
        Read until one from a list of a regular expressions matches.

        Use this to search for anything.

        :param regexes: The first argument is a list of regular expressions, either
            compiled (re.Pattern instances) or uncompiled (strings).
        :param timeout: Timeout in seconds. If none, default will be taken.
        :return: Return a tuple of three items: the index in the list of the
            first regular expression that matches; the re.Match object
            returned; and the text read up till and including the match.
        """
        if timeout is None:
            timeout = self.current_default_timeout

        if type(regexes) is str or type(regexes) is bytes:
            raise EnoException(
                "expect() takes a list(!) of strings or patterns as a parameter"
            )

        patterns: List[Pattern[bytes]] = [
            v if hasattr(v, "search") else re.compile(ensure_bytes(v)) for v in regexes  # type: ignore
        ]

        def patterns_match(buf: bytes) -> bool:
            for p in patterns:
                res = p.search(buf)
                if res is not None:
                    print(res)
                    return True
            return False

        return super().recvpred(patterns_match, timeout=timeout)

    def read_until(
        self, match: Union[bytes, str], timeout: Optional[float] = None
    ) -> bytes:
        """
        Read until the expected string has been seen, or a timeout is hit
        (default is default socket timeout).

        :param match: what to look for.
        :param timeout: default socket timeout override
        :return: Returns everything until the given math. When no match is found, return whatever is available instead,
            possibly the empty string.  Raise EOFError if the connection
            is closed and no cooked data is available.
        """

        if timeout is None:
            timeout = self.current_default_timeout

        return super().recvuntil(match, timeout=timeout)

    def read_n_lines(
        self, line_count: int, delimiter: Union[str, bytes] = b"\n"
    ) -> List[bytes]:
        r"""
        Read n lines from socket.

        :param line_count: the amount of lines to read
        :param delimiter: what delimeter to use for splitting (could also be non-\n)
        :return: a list of lines
        """
        return [self.read_until(ensure_bytes(delimiter)) for _ in range(line_count)]

    def read_all(self) -> bytes:
        """
        Read all data until EOF; block until connection closed.

        :return: the complete content until EOF
        """
        return super().recvall()

    def write(self, buffer: Union[str, bytes]) -> None:
        """
        Write a string to the socket.

        Can block if the connection is blocked.
        May raise socket.error if the connection is closed.

        :param buffer: The buffer to write
        """
        super().send(ensure_bytes(buffer))
