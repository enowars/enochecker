import socket

from future.standard_library import install_aliases

install_aliases()

import argparse
import json
import logging
import sys
from abc import ABCMeta, abstractmethod
from typing import Optional, Callable, Any, Dict
from urllib.parse import urlparse

import requests
from future.utils import with_metaclass
from requests import HTTPError, ConnectTimeout, ConnectionError

from concurrent.futures import TimeoutError

from .utils import snake_caseify, SimpleSocket
from .storeddict import StoredDict, DB_DEFAULT_DIR
from .useragents import random_useragent
from .results import Result, EnoException

if "TimeoutError" not in globals():  # Python2
    # noinspection PyShadowingBuiltins
    TimeoutError = socket.timeout

logging.basicConfig(level=logging.DEBUG)
logger = logging.Logger(__name__)
logger.setLevel(logging.DEBUG)

VALID_ARGS = ["method", "address", "port", "team_name", "round", "flag", "max_time", "call_idx"]

CHECKER_METHODS = [
    "StoreFlag",
    "RetrieveFlag",
    "StoreNoise",
    "RetrieveNoise",
    "Havoc"
]


def parse_args(argv=None):
    # type: (argparse.Namespace) -> argparse.Namespace
    """
    Returns the parsed argparser args.
    Args look like this:
    [
        "StoreFlag|RetrieveFlag|StoreNoise|RetrieveNoise|Havoc", [Task type]
        "$Address", [Address, either IP or domain]
        "$TeamName",
        "$Round",
        "$Flag|$Noise",
        "$MaxRunningTime",
        "$CallIdx" [index of this task (for each type) in the current round]
    ]
    :param argv: argv. Custom argvs. Will default to sys.argv if not provided.
    :return: args object
    """
    if argv is None:
        argv = parse_args(sys.argv[1:])
    parser = argparse.ArgumentParser(description="Your friendly checker script")
    parser.add_argument('method', choices=CHECKER_METHODS,
                        help='The Method, one of {}'.format(CHECKER_METHODS))
    parser.add_argument('address', type=str,
                        help="The ip or address of the remote team to check")
    parser.add_argument('team_name', type=str,
                        help="The teamname team to check")
    parser.add_argument('round', type=int,
                        help="The round we are in right now")
    parser.add_argument('flag', type=str,
                        help="The Flag, a Fake flag or a Unique ID, depending on the mode")
    parser.add_argument('max_time', type=int,
                        help="The maximum amount of time the script has to execute")
    parser.add_argument('call_idx', type=int,
                        help="Unique numerical index per round. Each id only occurs once and is tighly packed, "
                             "starting with 0. In a service supporting multiple flags, this would be used to "
                             "decide which flag to place.")
    parser.add_argument('-p', '--port', nargs='?', type=int,
                        help="The port the script should use")
    return parser.parse_args(args=argv)  # type: argparse.Namespace


class BaseChecker(with_metaclass(ABCMeta, object)):
    """
    All you base are belong to us. Also all your flags. And checker scripts.
    Override the methods given here, then simply init and .run().
    Magic.
    """

    def __init__(self,
                 method=None, address=None, team_name=None, round=None, flag=None, call_idx=None,
                 max_time=None, port=None, storage_dir=DB_DEFAULT_DIR, from_args=True):
        # type: (Optional[str], Optional[str], Optional[str], Optional[int], Optional[str], Optional[int], Optional[int], Optional[int], str, bool) -> None
        """
        Inits the Checker, filling the params, according to:
        :param: method: The method
        :param: port for all networking methods of this checker
        :param: start_action set to false to not run the action
        :param: from_args: If true, uses parse_args() to fill all parameters that were passed as `None`.
        """
        self._setup_logger()
        self.storage_dir = storage_dir
        self._active_dbs = {}  # type: Dict[str, StoredDict]
        self.http_session = requests.session()  # type: requests.Session
        self.http_useragent = random_useragent()

        self.method = method  # type: str
        self.address = address  # type: str
        self.port = port  # type: int
        self.team_name = team_name  # type: str
        self.round = round  # type: int
        self.flag = flag  # type: str
        self.max_time = max_time  # type: int
        self.call_idx = call_idx  # type: int

        if from_args and any([(getattr(self, x) is None) for x in VALID_ARGS]):
            args = parse_args(sys.argv[1:])

            for key in VALID_ARGS:
                if getattr(self, key) is None:
                    val = getattr(args, key)
                    self.debug("Setting value {} from commandline to {}".format(key, val))
                    setattr(self, key, val)

        self.config = {x: getattr(self, x) for x in VALID_ARGS}
        self.debug("Initialized checker with {}".format(json.dumps(self.config)))

    def _setup_logger(self):
        # type: () -> None
        """
        Sets up a logger usable from inside a checker using
        self.debug, self.info, self.warning, self.error or self.logger
        A logger can have additional args as well as exc_info=True to log an exception, stack_info=True to log trace.
        """
        self.logger = logging.Logger(type(self).__name__)  # type: logging.Logger
        self.logger.setLevel(logging.DEBUG)
        self.debug = logging.debug  # type: Callable[[str, ...], None]
        self.info = logging.info  # type: Callable[[str, ...], None]
        self.warning = logging.warning  # type: Callable[[str, ...], None]
        self.error = logging.error  # type: Callable[[str, ...], None]

    @property
    def noise(self):
        # type: () -> str
        """
        Pretty similar to a flag, just in a different mode (storeNoise vs storeFlag)
        :return: The noise
        """
        return self.flag

    # ---- Basic checker functionality ---- #
    def run(self, method=None):
        # type: (Optional[str, Callable]) -> int
        """
        Executes the checker and catches errors along the way.
        :param method: When calling run, you may call a different method than the one passed on Checker creation
                        using this optional param.
        :return: the Result code as int, as per the Result enum.
        """
        try:
            if callable(method):
                ret = method()
            else:
                if method is None:
                    method = self.method
                if method not in CHECKER_METHODS:
                    raise ValueError("Method {} not supported! Supported: {}".format(method, CHECKER_METHODS))
                ret = getattr(self, snake_caseify(method))()
            if Result.is_valid(ret):
                logger.info("Checker [{}] resulted in {}".format(self.method, ret))
                return ret
            if ret is not None:
                logger.error("Illegal return value from {}: {}".format(self.method, ret), )
                return Result.INTERNAL_ERROR
            logger.info("Checker [{}] executed successfully!".format(self.method))
            return Result.OK

        except EnoException as eno:
            self.info("Checker[{}] result: {}({})".format(eno.result, self.method, eno), exc_info=True)
            return eno.result
        except HTTPError as ex:
            self.info("Service returned HTTP Errorcode [{}].".format(ex), exc_info=True)
            return Result.ENOWORKS
        except (
                ConnectionError,  # requests
                ConnectTimeout,  # requests
                TimeoutError,
                socket.timeout,
                ConnectionError,
                # ConnectionAbortedError,  # not in py2, already handled by ConnectionError.
                # ConnectionRefusedError
        ) as ex:
            self.info("Error in connection to service occurred: {}".format(ex), exc_info=True)
            return Result.OFFLINE
        except Exception as ex:
            self.error("Unhandled checker error occurred: {}".format(ex), exc_info=1)
            return Result.INTERNAL_ERROR
        finally:
            for db in self._active_dbs.values():
                # A bit of cleanup :)
                db.persist()

    @abstractmethod
    def store_flag(self):
        # type: () -> Optional[Result]
        """
        This method stores a flag in the service.
        In case multiple flags are provided, self.call_idx gives the appropriate index.
        The flag itself can be retrieved from self.flag.
        On error, raise an Eno Exception.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        pass

    @abstractmethod
    def retrieve_flag(self):
        # type: () -> Optional[Result]
        """
        This method retrieves a flag from the service.
        Use self.flag to get the flag that needs to be recovered and self.roudn to get the round the flag was placed in.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        pass

    @abstractmethod
    def store_noise(self):
        # type: () -> Optional[Result]
        """
        This method stores noise in the service. The noise should later be recoverable.
        The difference between noise and flag is, tht noise does not have to remain secret for other teams.
        This method can be called many times per round. Check how often using self.call_idx.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        pass

    @abstractmethod
    def retrieve_noise(self):
        # type: () -> Optional[Result]
        """
        This method retrieves noise in the service.
        The noise to be retrieved is inside self.flag
        The difference between noise and flag is, tht noise does not have to remain secret for other teams.
        This method can be called many times per round. Check how often using call_idx.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        pass

    @abstractmethod
    def havoc(self):
        # type: () -> Optional[Result]
        """
        This method unleashes havoc on the app -> Do whatever you must to prove the service still works. Or not.
        On error, raise an EnoException.
        :raises EnoException on Error
        :return This function can return a result if it wants
                If nothing is returned, the service status is considered okay.
                The preferred way to report Errors in the service is by raising an appropriate EnoException
        """
        pass

    # ---- DB specific methods ---- #
    def db(self, name, ignore_locks=False):
        # type: (str, bool) -> StoredDict
        """
        Get a (global) db by name
        Subsequent calls will return the same db.
        Names can be anything, for example the team name, round numbers etc.
        :param name: The name of the DB
        :param ignore_locks: Should only be set if you're sure-ish keys are never shared between instances.
                Manual locking ist still possible.
        :return: A dict that will be self storing. Alternatively,
        """
        try:
            return self._active_dbs[name]
        except KeyError:
            self.debug("DB {} was not cached.".format(name))
            ret = StoredDict(base_path=self.storage_dir, name=name, ignore_locks=ignore_locks)
            self._active_dbs[name] = ret
            return ret

    @property
    def global_db(self):
        # type: () -> StoredDict
        """
        A global storage shared between all teams and rounds.
        Subsequent calls will return the same db.
        Prefer db_team_local or db_round_local
        :return: The global db
        """
        return self.db("gobal")

    @property
    def team_db(self):
        # type: () -> StoredDict
        """
        The database for the current team
        :return: The team local db
        """
        return self.get_team_db()

    def get_team_db(self, team=None):
        # type: (Optional[str]) -> StoredDict
        """
        Returns the database for a specific team.
        Subsequent calls will return the same db.
        :param team: Return a db for an other team. If none, the db for the local team will be returned.
        :return: The team local db
        """
        team = team if team is not None else self.team_name
        return self.db("team_{}".format(team), ignore_locks=True)

    # ---- Networking specific methods ---- #
    def _sanitize_url(self, route, port=None, scheme=None):
        # type: (str, Optional[int], Optional[str]) -> str
        if port is None:
            port = self.port
        if port is None:
            raise ValueError("Port for service not set. Cannot Request.")
        netloc = "{}:{}".format(self.address, port)
        if scheme is None:
            url = urlparse(route)
        else:
            url = urlparse(route, scheme=scheme)
        # noinspection PyProtectedMember
        return url._replace(netloc=netloc).geturl()

    def connect(self, host=None, port=None, timeout=30):
        # type: (Optional[str], Optional[int], int) -> SimpleSocket
        """
        Opens a socket/telnet connection to the remote host.
        Use connect(..).get_socket() for the raw socket.
        :param host: the host to connect to (defaults to self.address)
        :param port: the port to connect to (defaults to self.port)
        :param timeout: timeout on connection
        :return: A connected Telnet instance
        """
        if port is None:
            port = self.port
        if host is None:
            host = self.address
        self.debug("Opening socket to {}:{} (timeout {} secs).".format(host, port, timeout))
        return SimpleSocket(host, port, timeout=timeout)

    @property
    def http_useragent(self):
        # type: () -> str
        """
        The useragent for http(s) requests
        :return: the current useragent
        """
        return self.http_session.headers["User-Agent"]

    @http_useragent.setter
    def http_useragent(self, useragent):
        # type: (str) -> None
        """
        Sets the useragent for http requests.
        Randomize using http_useragent_randomize()
        :param useragent: the useragent
        """
        self.http_session.headers["User-Agent"] = useragent

    def http_useragent_randomize(self):
        """
        Choses a new random http useragent.
        Note that http requests will be initialized with a random user agent already.
        To retrieve a random useragent without setting it, use random instead.
        :return: the new useragent
        """
        new_agent = random_useragent()
        self.http_useragent = new_agent
        return new_agent

    def http_post(self, route="/", params=None, port=None, scheme="http", raise_http_errors=False, timeout=30,
                  **kwargs):
        # type: (str, Any, Optional[int], str, bool, int, ...) -> requests.Response
        """
        Performs a requests.post to the current host.
        Caches cookies in self.http_session
        :param params: The parameter
        :param route: The route
        :param port: The remote port in case it has not been specified at creation
        :param scheme: The scheme (defaults to http)
        :param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
        :param timeout: How long we'll try to connect
        :return: The response
        """
        kwargs.setdefault('allow_redirects', True)
        return self.http("post", route, params, port, scheme, raise_http_errors, timeout, **kwargs)

    def http_get(self, route="/", params=None, port=None, scheme="http", raise_http_errors=False, timeout=30, **kwargs):
        # type: (str, Any, Optional[int], str, bool, int, ...) -> requests.Response
        """
        Performs a requests.get to the current host.
        Caches cookies in self.http_session
        :param params: The parameter
        :param route: The route
        :param port: The remote port in case it has not been specified at creation
        :param scheme: The scheme (defaults to http)
        :param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
        :param timeout: How long we'll try to connect
        :return: The response
        """
        kwargs.setdefault('allow_redirects', True)
        return self.http("get", route, params, port, scheme, raise_http_errors, timeout, **kwargs)

    def http(self, method, route="/", params=None, port=None, scheme="http", raise_http_errors=False, timeout=30,
             **kwargs):
        # type: (str, str, Any, Optional[int], str, bool, int, ...) -> requests.Response
        """
        Performs an http request (requests lib) to the current host.
        Caches cookies in self.http_session
        :param method: The request method
        :param params: The parameter
        :param route: The route
        :param port: The remote port in case it has not been specified at creation
        :param scheme: The scheme (defaults to http)
        :param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
        :param timeout: How long we'll try to connect
        :return: The response
        """
        url = self._sanitize_url(route, port, scheme)
        self.debug("Request: {} {} with params: {} and {} secs timeout.".format(method, url, params, timeout))
        resp = self.http_session.request(method, url, params=params, timeout=timeout, **kwargs)
        if raise_http_errors:
            resp.raise_for_status()
        return resp
