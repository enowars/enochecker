from future.standard_library import install_aliases

install_aliases()

import base64
import hashlib
import logging
import re
import socket
import telnetlib
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Union, Any, Optional, Dict, Callable


import requests
from .results import BrokenServiceException, OfflineException

PORT_MAX = 65535

logging.basicConfig(level=logging.DEBUG)
logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)


def assert_in(o1, o2, message=None):
    # type: (Any, Any, Optional[str]) -> None
    """
    Raises an exception if o1 not in o2
    :param o1: the object that should be in o2
    :param o2: the object to look in
    :param message: An optional message that will be part of the error
    """
    if message is None:
        message = "{} is not in {}".format(o1, o2)
    if not o2 or not o2 or o1 not in o2:
        raise BrokenServiceException(message)


def assert_equals(o1, o2, message=None, autobyteify=False):
    # type: (Any, Any, Optional[str], bool) -> None
    """
    Raises an exception if o1 != o2
    :param o1: the first object
    :param o2: the second object
    :param message: The exception message in case of an error (optional)
    :param autobyteify: will call ensure_bytes on both parameters.
    """
    if message is None:
        message = "{} is not equal to {}".format(o1, o2)
    if autobyteify:
        o1 = ensure_bytes(o1)
        o2 = ensure_bytes(o2)
    if o1 != o2:
        raise BrokenServiceException(message)


def ensure_bytes(obj):
    # type: (Union[bytes, str, Any]) -> bytes
    """Converts to bytes"""
    if obj is None:
        raise ValueError("Cannot byteify None")
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        return obj.encode("ascii")
    return str(obj).encode("ascii")


def ensure_unicode(obj):
    # type: (Union[bytes, str, Any]) -> str
    """Converts to utf-8"""
    if str is None:
        raise ValueError("Cannot stringify None")
    if isinstance(obj, bytes):
        return obj.decode("utf-8")
    if isinstance(obj, str):
        return obj
    return str(obj)


def ensure_valid_filename(s, min_length=3):
    # type: (str, int) -> str
    """
    Gets a valid file name from the input
    :param s: The input string
    :param min_length: if the result is smaller than this, the method will fall back to base64.
    :return: all illegal chars stripped or base64ified if it gets too small
    """
    orig = s
    s = str(s).strip().replace(' ', '_')
    s = re.sub(r'(?u)[^-\w.]', '', s)
    if len(s) < min_length:
        s = base64ify(orig)
    return s


def snake_caseify(camel):
    # type: (Union[str, bytes]) -> str
    """
    Turn camels into snake (-cases)
    :param camel: camelOrSnakeWhatever
    :return: camel_or_snake_whatever
    """
    camel = ensure_unicode(camel)
    half_snake = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', camel)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', half_snake).lower()


def sha256ify(s):
    # type: (Union[str, bytes]) -> str
    """
    Calculate the sha256 hash
    :param s: the string
    :return: the hash in hex representation
    """
    s = ensure_bytes(s)
    return hashlib.sha256(s).hexdigest()


def base64ify(s):
    # type: (Union[str, bytes]) -> str
    """
    Calculate the base64 representation of a value
    :param s: the input string
    :return: base64 representation
    """
    s = ensure_bytes(s)
    return base64.b64encode(s).decode("utf-8")


def debase64ify(s):
    # type: (Union[str, bytes]) -> str
    """
    Return a string out of a base64
    :param s: the string
    :return: the original value
    """
    s = ensure_bytes(s)
    return base64.b64decode(s).decode("utf-8")


def readline_expect(telnet, expected, read_until=b"\n", timeout=30):
    # type: (telnetlib.Telnet, Union[str, bytes], Union[str, bytes], int) -> bytes
    """
    Reads to newline (or read_until string) and assert the presence of a string in the response.
    Will raise an exception if failed.
    :param telnet: Connected telnet instance (the result of self.telnet(..))
    :param expected: the expected String to search for in the response
    :param read_until: Which char to read until.
    :param timeout: a timeout
    :return read: the bytes read
    """
    if isinstance(expected, str):
        expected = expected.encode("utf-8")
    if isinstance(read_until, str):
        read_until = read_until.encode("utf-8")

    read = telnet.read_until(read_until, timeout)
    if read == b"":
        err = "Expected {} but got nothing/timeout!".format(expected)
        logger.error(err, stack_info=True)
        telnet.close()
        raise OfflineException(err)
    if expected not in read:
        err = "Expected {} but got {}".format(expected, read)
        logger.error(err, stack_info=True)
        telnet.close()
        raise BrokenServiceException(err)
    return read


def start_daemon(target):
    # type: (Callable) -> threading.Thread
    """
    starts a thread as daemon
    :param target: the function
    :return: the started thread
    """
    t = threading.Thread(target=target)
    t.daemon = True
    t.start()
    return t


def serve_once(html, start_port=5000, autoincrement_port=True, content_type='text/html', headers=None):
    # type: (Union[str, bytes, requests.Response], int, bool, str, Optional[Dict[str, str]]) -> int
    """
    Render Text in the users browser
    Opens a web server that serves a HTML string once and shuts down after the first request.
    The port will be open when this function returns. (though serving the request may take a few mils)
    :param html: The html code to deliver on the initial request
    :param start_port: The port it should try to listen on first.
    :param autoincrement_port: If the port should be increased if the server cannot listen on the provided start_port
    :param content_type: The content type this server should report (change it if you want json, for example)
    :param headers: Additional headers as {header_key: value} dict.
    :return: The port the server started listening on
    """
    if headers is None:
        headers = {}
    if isinstance(html, requests.Response):
        html = html.text
    if isinstance(html, str):
        html = html.encode("UTF-8")

    class OutputHandler(BaseHTTPRequestHandler):

        # noinspection PyPep8Naming
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', content_type)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(html)
            logger.info("Served HTTP once. Stopping.")
            start_daemon(self.server.shutdown)

    for port in range(start_port, PORT_MAX):
        try:
            server = HTTPServer(('', port), OutputHandler)
            logging.debug("Serving {} bytes on port {}".format(len(html), port))
            start_daemon(server.serve_forever)
            time.sleep(0.1)  # some extra time thrown in for good measure. :)
            return port
        except socket.error as ex:
            if not autoincrement_port:
                logger.info("Serve once was not set to automatically increment port {} but faced socket exception{}".
                            format(start_port, ex), exc_info=True)
                break

    raise socket.error(
        "No unused port found, start_port={}, autoincrement_port={}".format(start_port, autoincrement_port))


class SimpleSocket(telnetlib.Telnet):
    """
    Telnetlib with some additions
    """

    def readline_expect(self, expected, read_until=b"\n", timeout=30):
        # type: (Union[str, bytes], Union[str, bytes], int) -> bytes
        """
        Reads to newline (or read_until string) and assert the presence of a string in the response.
        Will raise an exception if failed.
        :param read_until: Which parameter to read until
        :param expected: the expected String to search for in the response
        :param timeout: a timeout
        :return read: the bytes read
        """
        return readline_expect(self, expected, read_until, timeout)
