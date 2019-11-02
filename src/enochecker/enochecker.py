import datetime
import socket

from flask import Flask
from future.standard_library import install_aliases

install_aliases()

import argparse
import json
import logging
import os
import sys

from abc import ABCMeta, abstractmethod
from typing import Optional, Callable, Any, Dict, List, Union, Type, TYPE_CHECKING
from urllib.parse import urlparse

from future.utils import with_metaclass

from concurrent.futures import TimeoutError

from .utils import snake_caseify, SimpleSocket
from .useragents import random_useragent
from .results import Result, EnoException
from .checkerservice import init_service, CHECKER_METHODS
from .logging import RestLogHandler, ELKFormatter
from .storeddict import StoredDict, DB_DEFAULT_DIR, DB_GLOBAL_CACHE_SETTING
from .nosqldict import NoSqlDict

if TYPE_CHECKING:
    # The import might fail in UWSGI, see the comments below.
    import requests

TIME_BUFFER = 5  # type: int # time in seconds we try to finish earlier

VALID_ARGS = [
    "method",
    "address",
    "team",
    "team_id",
    "round",
    "flag_round",
    "flag",
    "timeout",
    "flag_idx",
    "json_logging",
    "log_endpoint",
    "round_length",
]

# Global cache for all stored dicts.  TODO: Prune this at some point?
global_db_cache = {}  # type: Dict[str, Union[StoredDict, NoSqlDict]]


def parse_args(argv=None):
    # type: (Union[None, List[str], argparse.Namespace]) -> argparse.Namespace
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
        return parse_args(sys.argv[1:])
    choices = CHECKER_METHODS + ["listen"]
    parser = argparse.ArgumentParser(description="Your friendly checker script")
    # noinspection SpellCheckingInspection
    subparsers = parser.add_subparsers(
        help="The checker runmode (run/listen)", dest="runmode"
    )
    subparsers.required = True

    listen = subparsers.add_parser("listen", help="Spawn checker service")
    listen.add_argument(
        "listen_port", help="The port the checker service should listen on"
    )

    runparser = subparsers.add_parser("run", help="Run checker on cmdline")
    runparser.add_argument(
        "method",
        choices=choices,
        help='The Method, one of {} or "listen" to start checker service'.format(
            CHECKER_METHODS
        ),
    )
    runparser.add_argument(
        "-a",
        "--address",
        type=str,
        default="localhost",
        help="The ip or address of the remote team to check",
    )
    runparser.add_argument(
        "-t",
        "--team",
        type=str,
        default="team",
        help="The name of the target team to check",
    )
    runparser.add_argument(
        "-T",
        "--team_id",
        type=int,
        default=1,
        help="The Team_id belonging to the specified Team",
    )
    runparser.add_argument(
        "-I",
        "--run_id",
        type=int,
        default=1,
        help="An id for this run. Used to find it in the DB later.",
    )
    runparser.add_argument(
        "-r", "--round", type=int, default=1, help="The round we are in right now"
    )
    runparser.add_argument(
        "-R",
        "--round_length",
        type=int,
        default=300,
        help="The round length in seconds (default 300)",
    )
    runparser.add_argument(
        "-f",
        "--flag",
        type=str,
        default="ENOFLAGENOFLAG=",
        help="The Flag, a Fake flag or a Unique ID, depending on the mode",
    )
    runparser.add_argument(
        "-F",
        "--flag_round",
        type=int,
        default=1,
        help="The Round the Flag belongs to (was placed)",
    )
    runparser.add_argument(
        "-x",
        "--timeout",
        type=int,
        default=30,
        help="The maximum amount of time the script has to execute in seconds",
    )
    runparser.add_argument(
        "-i",
        "--flag_idx",
        type=int,
        default=0,
        help="Unique numerical index per round. Each id only occurs once and is tighly packed, "
        "starting with 0. In a service supporting multiple flags, this would be used to "
        "decide which flag to place.",
    )
    runparser.add_argument(
        "-l",
        "--log_endpoint",
        type=str,
        default="",
        help="URI to an optional RESTlike service accepting log jsons via POST.",
    )
    runparser.add_argument(
        "-j",
        "--json_logging",
        dest="json_logging",
        action="store_true",
        help="If set, logging will be in ELK/Kibana friendly JSON format.",
    )

    return parser.parse_args(args=argv)  # (return is of type argparse.Namespace)


class _CheckerMeta(ABCMeta):
    """
    Some python magic going on right here.
    Each time we subclass BaseChecker, this __init__ is called.
    ABCMeta is used as superclass instead of type, such that BaseChecker is declared abstract -> needs to be overridden.
    """

    def __init__(cls, name, bases, clsdict):
        # type: (Type[_CheckerMeta], str, Dict[Any]) -> None
        """
        Called whenever this class is subclassed.
        :param name: The name of the new class
        :param bases: Bases classes this class inherits from.
        :param clsdict: Contents of this class (.__dict__)
        """
        if len(cls.mro()) > 2:  # 1==BaseChecker
            cls.service = init_service(cls)  # type: Flask
        super(_CheckerMeta, cls).__init__(name, bases, clsdict)


class BaseChecker(with_metaclass(_CheckerMeta, object)):
    """
    All you base are belong to us. Also all your flags. And checker scripts.
    Override the methods given here, then simply init and .run().
    Magic.
    """

    def __init__(
        self,
        request_dict: Dict[str, Any] = None,
        run_id: int = None,
        method: str = None,
        address: str = None,
        team: str = None,
        team_id: int = None,
        round: int = None,
        flag_round: int = None,
        round_length: int = 300,
        flag: str = None,
        flag_idx: int = None,
        timeout: int = None,
        storage_dir: str = DB_DEFAULT_DIR,
        log_endpoint: Optional[str] = None,
        use_db_cache: bool = DB_GLOBAL_CACHE_SETTING,
        json_logging: bool = True,
    ) -> None:
        """
        Inits the Checker, filling the params, according to:
        :param: run_id: Unique ID for this run, assigned by the ctf framework. Used as handle for logging.
        :param: method: The method to run
        """
        # We import requests after startup global imports may deadlock, see
        # https://github.com/psf/requests/issues/2925
        import requests

        self.requests = requests

        self.time_started_at = datetime.datetime.now()  # type: datetime
        self.run_id = run_id  # type: int
        self.log_endpoint = log_endpoint  # type: Optional[str]
        self.json_logging = json_logging  # type: bool

        self.method = method  # type: str
        self.address = address  # type: str
        self.team = team  # type: str
        self.team_id = team_id
        self.round = round  # type: int
        self.current_round = round
        self.flag_round = flag_round  # type: int
        self.round_length = round_length  # type: int
        self.flag = flag  # type: str
        self.timeout = timeout  # type: int

        self.flag_idx = flag_idx  # type: int
        self.storage_dir = storage_dir

        self._setup_logger()
        if use_db_cache:
            self._active_dbs = global_db_cache  # type: Dict[str, StoredDict]
        else:
            self._active_dbs = {}  # type: Dict[str, Union[NoSqlDict, StoredDict]]
        self.http_session = self.requests.session()  # type: requests.Session
        self.http_useragent = random_useragent()

        if not hasattr(self, "service_name"):
            self.service_name = type(self).__name__.split("Checker")[0]
            self.debug(
                "Assuming checker Name {}. If that's not the case, please override.".format(
                    self.service_name
                )
            )

        if not hasattr(self, "port"):
            self.warning("No default port defined.")
            self.port = -1

        self.request_dict = request_dict  # kinda duplicate
        self.config = {x: getattr(self, x) for x in VALID_ARGS}

        self.debug(
            "Initialized checker for flag {} with in {} seconds".format(
                json.dumps(self.config), datetime.datetime.now() - self.time_started_at
            )
        )

        if self.method == "havok":
            self.method = "havoc"
            self.warning("Ignoring method 'havok', calling 'havoc' instead")

    def _setup_logger(self):
        # type: () -> None
        """
        Sets up a logger usable from inside a checker using
        self.debug, self.info, self.warning, self.error or self.logger
        A logger can have additional args as well as exc_info=ex to log an exception, stack_info=True to log trace.
        """
        self.logger = logging.Logger(type(self).__name__)  # type: logging.Logger
        self.logger.setLevel(logging.DEBUG)

        # default handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        if self.json_logging:
            formatter = ELKFormatter(self)
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        if self.log_endpoint and self.log_endpoint.startswith("http"):
            self.logger.addHandler(RestLogHandler(self))

        self.debug = self.logger.debug  # type: Callable[[str, ...], None]
        self.info = self.logger.info  # type: Callable[[str, ...], None]
        self.warning = self.logger.warning  # type: Callable[[str, ...], None]
        self.error = self.logger.error  # type: Callable[[str, ...], None]

    @property
    def noise(self):
        # type: () -> str
        """
        Pretty similar to a flag, just in a different mode (storeNoise vs storeFlag)
        :return: The noise
        """
        return self.flag

    @property
    def time_running(self):
        # type: () -> float
        """
        How long this checker has been running
        :return: time this checker has been running for
        """
        return (datetime.datetime.now() - self.time_started_at).total_seconds()

    @property
    def time_remaining(self):
        # type: () -> int
        """
        Returns a remaining time that is save to be used as timeout (includes a buffer of TIME_BUFFER seconds)
        :return: A save number of seconds that may still be used
        """
        return max(int(self.timeout - self.time_running - TIME_BUFFER), 1)

    # def __format_internal_db_entry(name):
    #     return f"__Checker-Internals:{name}__"

    # ---- Basic checker functionality ---- #

    def run(self, method=None):
        # type: (Optional[str, Callable]) -> Result
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
                    raise ValueError(
                        "Method {} not supported! Supported: {}".format(
                            method, CHECKER_METHODS
                        )
                    )

                ignore_run = False
                if method == "getflag":
                    try:
                        ignore_run = not (
                            "OK"
                            == self.team_db[
                                f"__Checker-internals-RESULT:putflag,{self.flag_round},{self.flag_idx}__"
                            ]
                        )

                    except KeyError as ex:
                        self.info(
                            f"original putflag did not return successfully -- ignoring getflag for flag_round:{self.flag_round}, index: {self.flag_idx}"
                        )
                        ignore_run = True

                if method == "getnoise":
                    try:

                        ignore_run = not (
                            "OK"
                            == self.team_db[
                                f"__Checker-internals-RESULT:putnoise,{self.flag_round},{self.flag_idx}__"
                            ]
                        )

                    except KeyError as ex:
                        self.info(
                            f"original putnoise did not return successfully -- ignoring getnoise for flag_round:{self.flag_round}, index: {self.flag_idx}"
                        )
                        ignore_run = True

                if ignore_run:
                    self.debug("run ignored -- preemptively returned OK")
                    return Result.OK

                ret = getattr(self, snake_caseify(method))()
            if Result.is_valid(ret):
                ret = Result(
                    ret
                )  # Better wrap this, in case somebody returns raw ints (?)
                self.info("Checker [{}] resulted in {}".format(self.method, ret.name))
                self.team_db[
                    f"__Checker-internals-RESULT:{str(method)},{self.flag_round},{self.flag_idx}__"
                ] = ret.name
                return ret
            if ret is not None:
                self.error("Illegal return value from {}: {}".format(self.method, ret))
                return (
                    Result.INTERNAL_ERROR
                )  # , "Illegal return value from {}: {}".format(self.method, ret)

            # Returned Normally
            self.info("Checker [{}] executed successfully!".format(self.method))
            self.team_db[
                f"__Checker-internals-RESULT:{str(method)},{self.flag_round},{self.flag_idx}__"
            ] = "OK"
            return Result.OK

        except EnoException as eno:
            self.info(
                "Checker[{}] result: {}({})".format(self.method, eno.result.name, eno),
                exc_info=eno,
            )
            return Result(eno.result)  # , eno.message
        except self.requests.HTTPError as ex:
            self.info("Service returned HTTP Errorcode [{}].".format(ex), exc_info=ex)
            return Result.MUMBLE  # , "HTTP Error" #For now
        except (
            self.requests.ConnectionError,  # requests
            self.requests.ConnectTimeout,  # requests
            TimeoutError,
            socket.timeout,
            ConnectionError,
            socket.error,
            # ConnectionAbortedError,  # not in py2, already handled by ConnectionError.
            # ConnectionRefusedError
        ) as ex:
            self.info(
                "Error in connection to service occurred: {}\n".format(ex), exc_info=ex
            )
            return Result.OFFLINE  # , ex.message
        except Exception as ex:
            self.error("Unhandled checker error occurred: {}\n".format(ex), exc_info=ex)
            return Result.INTERNAL_ERROR  # , ex.message
        finally:
            for db in self._active_dbs.values():
                # A bit of cleanup :)
                db.persist()

    @abstractmethod
    def putflag(self):
        # type: () -> Optional[Result]
        """
        This method stores a flag in the service.
        In case multiple flags are provided, self.flag_idx gives the appropriate index.
        The flag itself can be retrieved from self.flag.
        On error, raise an Eno Exception.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        pass

    @abstractmethod
    def getflag(self):
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
    def putnoise(self):
        # type: () -> Optional[Result]
        """
        This method stores noise in the service. The noise should later be recoverable.
        The difference between noise and flag is that noise does not have to remain secret for other teams.
        This method can be called many times per round. Check how often using self.flag_idx.
        On error, raise an EnoException.
        :raises EnoException on error
        :return this function can return a result if it wants
                if nothing is returned, the service status is considered okay.
                the preferred way to report errors in the service is by raising an appropriate enoexception
        """
        pass

    @abstractmethod
    def getnoise(self):
        # type: () -> Optional[Result]
        """
        This method retrieves noise in the service.
        The noise to be retrieved is inside self.flag
        The difference between noise and flag is, tht noise does not have to remain secret for other teams.
        This method can be called many times per round. Check how often using flag_idx.
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

    @abstractmethod
    def exploit(self):
        # type: () -> Optional[Result]
        """
        This method is strictly for testing purposes and will hopefully not be called during the actual CTF.
        :raises EnoException on Error
        :return This function can return a result if it wants
                If nothing is returned, the service status is considered okay.
                The preferred way to report Errors in the service is by raising an appropriate EnoException
        """
        pass

    # ---- DB specific methods ---- #
    def db(self, name, ignore_locks=False):
        # type: (str, bool) -> Union[NoSqlDict, StoredDict]
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
            db = self._active_dbs[name]
            db.logger = self.logger
            # TODO: Settng a new Logger backend may throw logs in the wrong direction in a multithreaded environment!
            return db
        except KeyError:
            checker_name = type(self).__name__
            self.debug("Remote DB {} was not cached.".format(name))
            if os.getenv("MONGO_ENABLED"):
                host = os.getenv("MONGO_HOST")
                port = int(os.getenv("MONGO_PORT"))
                username = os.getenv("MONGO_USER")
                password = os.getenv("MONGO_PASSWORD")
                self.debug(
                    "Using NoSqlDict mongo://{}:{}@{}:{}".format(
                        username, "".join(["X" for c in password]), host, port
                    )
                )

                ret = NoSqlDict(
                    name=name,
                    checker_name=checker_name,
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                )
            else:
                self.debug(
                    "MONGO_ENABLED not set. Using stored dict at {}".format(
                        self.storage_dir
                    )
                )
                ret = StoredDict(
                    name=name,
                    base_path=self.storage_dir,
                    ignore_locks=ignore_locks,
                    logger=self.logger,
                )
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
        return self.db("global")

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
        team = team if team is not None else self.team
        return self.db("team_{}".format(team), ignore_locks=True)

    # ---- Networking specific methods ---- #
    def _sanitize_url(self, route, port=None, scheme=None):
        # type: (str, Optional[int], Optional[str]) -> str
        if port is None:
            port = self.port
        if port is None:
            raise ValueError("Port for service not set. Cannot Request.")

        if ":" in self.address:
            netloc = "[{}]:{}".format(self.address, port)
        else:
            netloc = "{}:{}".format(self.address, port)
        if scheme is None:
            url = urlparse(route)
        else:
            url = urlparse(route, scheme=scheme)
        # noinspection PyProtectedMember
        return url._replace(netloc=netloc).geturl()

    def connect(self, host=None, port=None, timeout=None):
        # type: (Optional[str], Optional[int], Optional[int]) -> SimpleSocket
        """
        Opens a socket/telnet connection to the remote host.
        Use connect(..).get_socket() for the raw socket.
        :param host: the host to connect to (defaults to self.address)
        :param port: the port to connect to (defaults to self.port)
        :param timeout: timeout on connection (defaults to self.timeout)
        :return: A connected Telnet instance
        """
        timeout_fun = lambda: timeout
        if timeout is None:
            timeout = self.time_remaining / 2
            timeout_fun = lambda: self.time_remaining / 2
        if port is None:
            port = self.port
        if host is None:
            host = self.address
        self.debug(
            "Opening socket to {}:{} (timeout {} secs).".format(host, port, timeout)
        )
        return SimpleSocket(
            host, port, timeout=timeout, logger=self.logger, timeout_fun=timeout_fun
        )

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

    def http_post(
        self,
        route="/",
        params=None,
        port=None,
        scheme="http",
        raise_http_errors=False,
        timeout=None,
        **kwargs,
    ):
        # type: (str, Any, Optional[int], str, bool, Optional[int], ...) -> "requests.Response"
        """
        Performs a (http) requests.post to the current host.
        Caches cookies in self.http_session
        :param params: The parameter
        :param route: The route
        :param port: The remote port in case it has not been specified at creation
        :param scheme: The scheme (defaults to http)
        :param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
        :param timeout: How long we'll try to connect
        :return: The response
        """
        kwargs.setdefault("allow_redirects", False)
        return self.http(
            "post", route, params, port, scheme, raise_http_errors, timeout, **kwargs
        )

    def http_get(
        self,
        route="/",
        params=None,
        port=None,
        scheme="http",
        raise_http_errors=False,
        timeout=None,
        **kwargs,
    ):
        # type: (str, Any, Optional[int], str, bool, Optional[int], ...) -> "requests.Response"
        """
        Performs a (http) requests.get to the current host.
        Caches cookies in self.http_session
        :param params: The parameter
        :param route: The route
        :param port: The remote port in case it has not been specified at creation
        :param scheme: The scheme (defaults to http)
        :param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
        :param timeout: How long we'll try to connect
        :return: The response
        """
        kwargs.setdefault("allow_redirects", False)
        return self.http(
            "get", route, params, port, scheme, raise_http_errors, timeout, **kwargs
        )

    def http(
        self,
        method,
        route="/",
        params=None,
        port=None,
        scheme="http",
        raise_http_errors=False,
        timeout=None,
        **kwargs,
    ):
        # type: (str, str, Any, Optional[int], str, bool, Optional[int], ...) -> "requests.Response"
        """
        Performs an http request (requests lib) to the current host.
        Caches cookies in self.http_session
        :param method: The request method
        :param params: The parameter
        :param route: The route
        :param port: The remote port in case it has not been specified at creation
        :param scheme: The scheme (defaults to http)
        :param raise_http_errors: If True, will raise exception on http error codes (4xx, 5xx)
        :param timeout: How long we'll try to connect (default: self.timeout)
        :return: The response
        """
        kwargs.setdefault("allow_redirects", False)
        url = self._sanitize_url(route, port, scheme)
        if timeout is None:
            timeout = self.time_remaining / 2
        self.debug(
            "Request: {} {} with params: {} and {} secs timeout.".format(
                method, url, params, timeout
            )
        )
        resp = self.http_session.request(
            method, url, params=params, timeout=timeout, **kwargs
        )
        if raise_http_errors:
            resp.raise_for_status()
        return resp


def run(checker_cls, args=None):
    # type: (Type[BaseChecker], Union[None, List[str], argparse.Namespace]) -> None
    """
    # Runs a checker, either from cmdline or as uwsgi script.
    :param checker: The checker (subclass of basechecker) to run
    :param force_service: if True (non-default), the server will skip arg parsing and immediately spawn the web service.
    :param args: optional parameter, providing parameters
    :return:  Never returns.
    """
    parsed = parse_args(args)
    if parsed.runmode == "listen":
        checker_cls.service.run(host="::", debug=True, port=parsed.listen_port)
    else:
        checker_args = vars(parsed)
        del checker_args["runmode"]  # will always be 'run' at this point
        result = checker_cls(**vars(parsed)).run()
        print("Checker run resulted in Result.{}".format(result.name))
        return result
