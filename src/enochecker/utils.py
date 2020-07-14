"""Collection of utilities for checker development."""

import base64
import hashlib
import logging
import re
import socket
import telnetlib
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import (
    TYPE_CHECKING,
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

from .results import BrokenServiceException

if TYPE_CHECKING:  # pragma: no cover
    import requests

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
    if message is None:
        message = "Received unexpected response."
    if not o2 or o1 not in o2:
        raise BrokenServiceException(message)


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
    if message is None:
        message = "Received unexpected response."
    if autobyteify:
        o1 = ensure_bytes(o1)
        o2 = ensure_bytes(o2)
    if o1 != o2:
        raise BrokenServiceException(message)


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


def ensure_unicode(obj: Union[bytes, str, Any]) -> str:
    """
    Convert an object to an utf-8-encoded string.

    :param obj: str or bytes (or anything else) to convert to string representation
    :return: the string representation of the object
    """
    if obj is None:
        raise ValueError("Cannot stringify None")
    if isinstance(obj, bytes):
        return obj.decode("utf-8")
    if isinstance(obj, str):
        return obj
    return str(obj)


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


def snake_caseify(camel: Union[str, bytes]) -> str:
    """
    Turn camels into snake (-cases).

    :param camel: camelOrSnakeWhatever
    :return: camel_or_snake_whatever
    """
    camel = ensure_unicode(camel)
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


# def readline_expect(
#     telnet: Union[telnetlib.Telnet, "SimpleSocket"],
#     expected: Union[str, bytes],
#     read_until: Union[str, bytes] = b"\n",
#     timeout: int = 30,
# ) -> bytes:
#     """
#     Read to newline (or read_until string) and assert the presence of a string in the response.

#     Will raise an exception if failed.

#     :param telnet: Connected telnet instance (the result of self.telnet(..))
#     :param expected: the expected String to search for in the response
#     :param read_until: Which char to read until.
#     :param timeout: a timeout
#     :return: the bytes read
#     """
#     logger = getattr(telnet, "logger", utilslogger)

#     if isinstance(expected, str):
#         expected = expected.encode("utf-8")
#     if isinstance(read_until, str):
#         read_until = read_until.encode("utf-8")

#     read = telnet.read_until(read_until, timeout)
#     if read == b"":
#         err = "Expected {!r} but got nothing/timeout!".format(expected)
#         logger.error(err, stack_info=True)
#         telnet.close()
#         raise OfflineException(err)
#     if expected not in read:
#         err = "Expected {!r} but got {!r}".format(expected, read)
#         logger.error(err, stack_info=True)
#         telnet.close()
#         raise BrokenServiceException(err)
#     return read


def start_daemon(target: Callable[..., Any]) -> threading.Thread:
    """
    Start a thread as daemon.

    :param target: the function
    :return: the started thread
    """
    t = threading.Thread(target=target)
    t.daemon = True
    t.start()
    return t


def serve_once(
    html: Union[str, bytes, "requests.Response"],
    start_port: int = 5000,
    autoincrement_port: bool = True,
    content_type: str = "text/html",
    headers: Optional[Dict[str, str]] = None,
    logger: Optional[logging.Logger] = None,
) -> int:
    """
    Render Text in the users browser.

    Opens a web server that serves a HTML string once and shuts down after the first request.
    The port will be open when this function returns. (though serving the request may take a few mils)

    :param html: The html code to deliver on the initial request
    :param start_port: The port it should try to listen on first.
    :param autoincrement_port: If the port should be increased if the server cannot listen on the provided start_port
    :param content_type: The content type this server should report (change it if you want json, for example)
    :param headers: Additional headers as {header_key: value} dict.
    :param logger: the optional logger to redirect logs to.
    :return: The port the server started listening on
    """
    # see https://github.com/psf/requests/issues/2925
    import requests

    logger_: logging.Logger = logger or utilslogger
    headers_: Dict[str, str] = headers or {}
    if isinstance(html, requests.Response):
        payload: bytes = html.text.encode("UTF-8")
    elif isinstance(html, str):
        payload = html.encode("UTF-8")
    else:
        payload = html

    class OutputHandler(BaseHTTPRequestHandler):

        # noinspection PyPep8Naming
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-type", content_type)
            for key, value in headers_.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)
            logger_.info("Served HTTP once. Stopping.")
            start_daemon(self.server.shutdown)

    for port in range(start_port, PORT_MAX):
        try:
            server = HTTPServer(("", port), OutputHandler)
            logging.debug("Serving {} bytes on port {}".format(len(payload), port))
            start_daemon(server.serve_forever)
            time.sleep(0.1)  # some extra time thrown in for good measure. :)
            return port
        except OSError as ex:
            if not autoincrement_port:
                logger_.info(
                    "Serve once was not set to automatically increment port {} but faced socket exception{}".format(
                        start_port, ex
                    ),
                    exc_info=True,
                    stack_info=True,
                )
                break

    raise OSError(
        "No unused port found, start_port={}, autoincrement_port={}".format(
            start_port, autoincrement_port
        )
    )


class SimpleSocket(telnetlib.Telnet):
    """
    Telnetlib with some additions.

    Read Telnetlib doku for more.
    """

    # pylint:  disable=protected-access
    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 0,
        timeout: int = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore
        logger: Optional[logging.Logger] = None,
        timeout_fun: Optional[Callable[[], int]] = None,
    ) -> None:
        """
        Initialize a new SimpleSocket Object.

        :param host: the host to connect to
        :param port: the port to connect to
        :param timeout: The timeout passed in here counts for the whole session.
        :param logger: The optional logger to use
        :param timeout_fun: function that will output the current timeout on each call.
        """
        super().__init__(host, port, timeout)
        self.socket: socket.socket = super().get_socket()
        if logger:
            self.logger = logger
        else:
            self.logger = utilslogger
        self.timeout_fun: Optional[Callable[[], int]] = timeout_fun

    @property
    def current_default_timeout(self) -> int:
        """
        Get the timeout default that should currently be used.

        :return: current timeout default, either from self.timeout_fun or from timeout.
        """
        if self.timeout_fun:
            return self.timeout_fun()
        else:
            return self.timeout  # type: ignore

    def readline_expect(
        self,
        expected: Union[str, bytes],
        read_until: Union[str, bytes] = b"\n",
        timeout: Optional[int] = None,
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
        timeout: Optional[int] = None,
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

        # Make sure all strings are bytes, ignore compiled Regexes.
        regexes_: List[Union[Pattern[bytes], bytes]] = [
            ensure_bytes(x) if isinstance(x, str) else x for x in regexes
        ]

        return super().expect(list=regexes_, timeout=timeout)

    def read_until(
        self, match: Union[bytes, str], timeout: Optional[int] = None
    ) -> bytes:
        """
        Read until the expected string has been seen, or a timeout is hit (default is default socket timeout).

        :param match: what to look for.
        :param timeout: default socket timeout override
        :return: Returns everything until the given math. When no match is found, return whatever is available instead,
            possibly the empty string.  Raise EOFError if the connection
            is closed and no cooked data is available.
        """
        if timeout is None:
            timeout = self.current_default_timeout
        return super().read_until(ensure_bytes(match), timeout)

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
        return super().read_all()

    def write(self, buffer: Union[str, bytes]) -> None:
        """
        Write a string to the socket.

        Can block if the connection is blocked.
        May raise socket.error if the connection is closed.

        :param buffer: The buffer to write
        """
        super().write(ensure_bytes(buffer))
