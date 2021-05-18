"""Collection of utilities for checker development."""

import base64
import hashlib
import logging
import re
import socket
import telnetlib
import time
import selectors
from typing import Any, Callable, List, Match, Optional, Pattern, Sequence, Tuple, Union

from .results import BrokenServiceException

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


class SimpleSocket:
    """
    Convenient socket.socker wrapper
    """

    # pylint:  disable=protected-access
    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 0,
        timeout: float = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore
        logger: Optional[logging.Logger] = None,
        timeout_fun: Optional[Callable[[], float]] = None,
    ) -> None:
        """
        Initialize a new SimpleSocket Object.

        :param host: the host to connect to
        :param port: the port to connect to
        :param timeout: The timeout passed in here counts for the whole session.
        :param logger: The optional logger to use
        :param timeout_fun: function that will output the current timeout on each call.
        """
        self.eof: bool = False
        self.timeout: float = 0
        self.socket: socket.socket = socket.create_connection((host, port), timeout)
        self.timeout_fun: Optional[Callable[[], float]] = timeout_fun
        if logger:
            self.logger = logger
        else:
            self.logger = utilslogger

    @property
    def current_default_timeout(self) -> float:
        """
        Get the timeout default that should currently be used.

        :return: current timeout default, either from self.timeout_fun or from timeout.
        """
        if self.timeout_fun:
            return self.timeout_fun()
        else:
            return self.timeout  # type: ignore

    def read_until_satisfied(
            self,
            checkfunc: Callable[[str], Union[int,tuple]],
            timeout: Optional[float] = None
    ) -> bytes:
        """
        :param checkfunc: checking function that returns the index in the buffer below
            which data should be returned, the rest can should stay in the socket buffer.
            a return value less than 0 signifies, that the check is not yet satisfied
            and more data should be received as long as the timeout has not run out
        :param timeout: how long to wait until checkfunc is satisfied
        :return: data received from socket up until the index returned by checkfunc
        """
        if timeout is None:
            timeout = self.current_default_timeout

        buf = b""
        extraret = None
        deadline = time.time() + timeout
        with selectors.SelectSelector() as selector:
            selector.register(self.socket, selectors.EVENT_READ)
            while not self.eof:
                if selector.select(timeout):
                    # this recv() wont block since atleast 1 byte is available
                    new = self.socket.recv(64, socket.MSG_PEEK)
                    ret = checkfunc(buf + new)
                    if type(ret) is tuple:
                        ind, extraret = ret
                    else:
                        ind = ret
                    if ind >= 0:
                        if ind <= len(buf):
                            raise Exception("checkfunc returned index outside of newly added data")
                        else:
                            buf += self.socket.recv(ind - len(buf))
                timeout = deadline - time.time()
                if timeout < 0:
                    break
        return buf, extraret

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

        :param regexes: The first argument is a list of regular expressions, either
            compiled (re.Pattern instances) or uncompiled (strings).
        :param timeout: Timeout in seconds. If none, default will be taken.
        :return: Return a tuple of three items: the index in the list of the
            first regular expression that matches; the re.Match object
            returned; and the text read up till and including the match.
        """

        if timeout is None:
            timeout = self.current_default_timeout

        # compile all normal strings / bytes into patterns
        regexes = regexes[:]
        for i in range(len(regexes)):
            if not hasattr(regexes[i], "search"):
                regexes[i] = re.compile(ensure_bytes(regexes[i]))

        def check_patterns(buf):
            for i in range(len(regexes)):
                match = regexes[i].search(buf)
                if match:
                    return match.end(), (i, match)
            return -1

        buf, (index, match) = self.read_until_satisfied(check_patterns, timeout)

        return (index, match, buf)

    def read_until(
        self,
        match: Union[bytes, str],
        timeout: Optional[float] = None
    ) -> bytes:
        """
        Read until the expected string has been seen, or a timeout is hit (default is default socket timeout).

        :param match: what to look for.
        :param timeout: default socket timeout override
        :return: Returns everything until the given math. When no match is found, return whatever is available instead,
            possibly the empty string.  Raise EOFError if the connection
            is closed and no cooked data is available.
        """

        if self.eof:
            raise EOFError("connection is closed")

        match = ensure_bytes(match)

        def check_suffix(buf):
            index = buf.find(match)
            if index >= 0:
                return index + len(match)
            else:
                return -1

        buf, _ = self.read_until_satisfied(check_suffix, timeout)

        return buf

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
        buf = b""
        while True:
            new = self.socket.recv(64)
            self.eof = not new
            if self.eof: break
            buf += new
        return buf

    def write(self, buffer: Union[str, bytes]) -> None:
        """
        Write a string to the socket.

        Can block if the connection is blocked.
        May raise socket.error if the connection is closed.

        :param buffer: The buffer to write
        """
        self.socket.sendall(ensure_bytes(buffer))
