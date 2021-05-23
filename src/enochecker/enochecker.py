"""Contains the BaseChecker to be used as base for all checkers."""

import argparse
import datetime
import hashlib
import logging
import os
import re
import socket
import sys
import traceback
import warnings
from abc import ABCMeta, abstractmethod
from concurrent.futures import TimeoutError
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
    cast,
)
from urllib.parse import urlparse

import jsons
from enochecker_cli import add_arguments, task_message_from_namespace
from enochecker_core import CheckerMethod, CheckerTaskMessage, CheckerTaskResult
from flask import Flask

from .checkerservice import init_service
from .logging import ELKFormatter
from .nosqldict import NoSqlDict
from .results import CheckerResult, EnoException, OfflineException
from .storeddict import DB_DEFAULT_DIR, DB_GLOBAL_CACHE_SETTING, StoredDict
from .useragents import random_useragent
from .utils import SimpleSocket, snake_caseify

if TYPE_CHECKING:  # pragma: no cover
    # The import might fail in UWSGI, see the comments below.
    import requests

DEFAULT_TIMEOUT: float = 30
TIME_BUFFER: float = 5  # time in seconds we try to finish earlier

# Global cache for all stored dicts.  TODO: Prune this at some point?
global_db_cache: Dict[str, Union[StoredDict, NoSqlDict]] = {}


def warn_deprecated(old_name: str, new_name: str) -> None:
    """
    Print a warning for the deprecated feature, include the new name in the log
    This needs python development mode or deprecation warnings enabled!
    """
    warnings.warn(
        f"Checker uses deprecated {old_name}; use {new_name} instead.",
        DeprecationWarning,
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """
    Return the parsed argparser args.

    :param argv: argv. Custom argvs. Will default to sys.argv if not provided.
    :return: args object
    """
    if argv is None:
        return parse_args(sys.argv[1:])
    parser = argparse.ArgumentParser(description="Your friendly checker script")
    parser.add_argument(
        "-j",
        "--disable-json-logging",
        action="store_true",
        help="Disable the JSON (ENOLOGMESSAGE) output",
    )

    subparsers = parser.add_subparsers(
        help="The checker runmode (run/listen)", dest="runmode"
    )
    subparsers.required = True

    listen = subparsers.add_parser("listen", help="Spawn checker service")
    listen.add_argument(
        "listen_port", help="The port the checker service should listen on"
    )

    runparser = subparsers.add_parser("run", help="Run checker on cmdline")
    add_arguments(runparser)

    return parser.parse_args(args=argv)


class _CheckerMeta(ABCMeta):
    """
    Some python magic going on right here.

    Each time we subclass BaseChecker, this __init__ is called.
    ABCMeta is used as superclass instead of type, such that BaseChecker is declared abstract -> needs to be overridden.
    """

    def __init__(
        cls: "_CheckerMeta", name: str, bases: Tuple[type, ...], clsdict: Dict[Any, Any]
    ):
        """
        Called whenever this class is subclassed.

        :param name: The name of the new class
        :param bases: Bases classes this class inherits from.
        :param clsdict: Contents of this class (.__dict__)
        """
        if len(cls.mro()) > 2:  # 1==BaseChecker
            cls.service: Flask = init_service(cast(Type[BaseChecker], cls))
        super().__init__(name, bases, clsdict)


class BaseChecker(metaclass=_CheckerMeta):
    """
    All you base are belong to us. Also all your flags. And checker scripts.

    Override the methods given here, then simply init and .run().
    Magic.
    """

    flag_variants: int
    noise_variants: int
    havoc_variants: int
    exploit_variants: int

    def __init__(
        self,
        task: CheckerTaskMessage,
        storage_dir: str = DB_DEFAULT_DIR,
        use_db_cache: bool = DB_GLOBAL_CACHE_SETTING,
        json_logging: bool = True,
    ) -> None:
        """
        Init the Checker, fill the params.

        :param task: The CheckerTaskMessage to be executed
        :param storage_dir: The directory to store persistent data in (used by StoredDict)
        :param use_db_cache: whether the DB connections should be cached or a new DB connection should be created per request
        :param json_logging: whether the JSON-based log format for ELK should be used instead of the more human-readable output
        """
        # We import requests after startup global imports may deadlock, see
        # https://github.com/psf/requests/issues/2925
        import requests

        self.requests = requests

        self.time_started_at: datetime.datetime = datetime.datetime.now()
        self.task_id: int = task.task_id
        self.json_logging: bool = json_logging

        self.method: CheckerMethod = task.method
        self.address: str = task.address
        self.team_id: int = task.team_id
        self.team_name: str = task.team_name
        self.current_round_id: int = task.current_round_id
        self.related_round_id: int = task.related_round_id
        self.flag: Optional[str] = task.flag
        self.variant_id: int = task.variant_id
        self.timeout: float = task.timeout / 1000
        self.round_length: float = task.round_length / 1000
        self.task_chain_id: str = task.task_chain_id
        self.flag_regex: Optional[str] = task.flag_regex
        if self.flag_regex:
            self._flag_regex: re.Pattern = re.compile(self.flag_regex)
            self._flag_regex_bytes: re.Pattern = re.compile(self.flag_regex.encode())
        self.flag_hash: Optional[str] = task.flag_hash
        self.attack_info: Optional[str] = task.attack_info

        self._noise_cache: Optional[str] = None

        self.storage_dir = storage_dir

        self._setup_logger()
        if use_db_cache:
            self._active_dbs: Dict[str, Union[NoSqlDict, StoredDict]] = global_db_cache
        else:
            self._active_dbs = {}
        self.http_session: requests.Session = self.requests.session()
        self.http_useragent = random_useragent()

        if not hasattr(self, "service_name"):
            self.service_name: str = type(self).__name__.split("Checker")[0]
            self.debug(
                "Assuming checker Name {}. If that's not the case, please override.".format(
                    self.service_name
                )
            )

        if not hasattr(self, "port"):
            self.warning("No default port defined.")
            self.port = -1

        self.debug(
            "Initialized checker for task {} in {} seconds".format(
                jsons.dumps(task),
                datetime.datetime.now() - self.time_started_at,
            )
        )

    def _setup_logger(self) -> None:
        """
        Set up a logger usable from inside a checker using.

        self.debug, self.info, self.warning, self.error or self.logger
        A logger can have additional args as well as exc_info=ex to log an exception, stack_info=True to log trace.
        """
        self.logger: logging.Logger = logging.Logger(type(self).__name__)
        self.logger.setLevel(logging.DEBUG)

        # default handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        if self.json_logging:
            formatter: logging.Formatter = ELKFormatter(self)
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.debug: Callable[..., None] = self.logger.debug
        self.info: Callable[..., None] = self.logger.info
        self.warning: Callable[..., None] = self.logger.warning
        self.error: Callable[..., None] = self.logger.error
        self.critical: Callable[..., None] = self.logger.critical

    @property
    def chain_db(self) -> Any:
        """
        get the team_db entry for the current chain. Short hand version for self.team_db[self.task_chain_id]

        :return: the team_db entry
        """
        return self.team_db[self.task_chain_id]

    @chain_db.setter
    def chain_db(self, value: Any) -> None:
        """
        set the team_db entry for the current task chain. Short hand version for self.team_db[self.task_chain_id] = value

        :param value: the value to set in the team_db
        """
        self.team_db[self.task_chain_id] = value

    @property
    def noise(self) -> str:
        """
        Creates a stable noise value for the current task chain.
        Do not use for indexing (use self.task_chain_id instead).

        :return: A noise string, unique for each task_chain_id.
        """
        if self._noise_cache is None:
            if not self.task_chain_id:
                self.warning("No valid task_chain_id when calling noise!")
                return "<none>"
            # We cache the hex in case it's called often.
            m = hashlib.sha256()
            m.update(self.task_chain_id.encode())
            self._noise_cache = m.hexdigest()
        return self._noise_cache

    @property
    def time_running(self) -> float:
        """
        How long this checker has been running for.

        :return: time this checker has been running for in seconds
        """
        return (datetime.datetime.now() - self.time_started_at).total_seconds()

    @property
    def time_remaining(self) -> float:
        """
        Return a remaining time that is safe to be used as timeout.

        Includes a buffer of TIME_BUFFER seconds.

        :return: A safe number of seconds that may still be used
        """
        return max(
            getattr(self, "timeout", DEFAULT_TIMEOUT) - self.time_running - TIME_BUFFER,
            1,
        )

    # ---- Basic checker functionality ---- #

    def _run_method(
        self, method: CheckerMethod
    ) -> Optional[Union[CheckerTaskResult, str]]:
        """
        Execute a checker method, pass all exceptions along to the calling function.

        :param method: When calling run, you may call a different method than the one passed on Checker creation
                        using this optional param.
        :return: a CheckerTaskResult enum value
        """

        return getattr(self, snake_caseify(method.value))()

    def run(self, method: Optional[CheckerMethod] = None) -> CheckerResult:
        """
        Execute the checker and catch errors along the way.

        :param method: When calling run, you may call a different method than the one passed on Checker creation
                        using this optional param.
        :return: A CheckerResult as a representation of the CheckerResult response as definded in the Spec.
        """
        if method is None:
            method = self.method

        try:
            ret = self._run_method(method)
            if method == CheckerMethod.EXPLOIT and (type(ret) == str or ret is None):
                if type(ret) == str:
                    self.info(
                        "Checker [{}] executed successfully and returned found flag: {}".format(
                            method, ret
                        )
                    )
                    return CheckerResult(CheckerTaskResult.OK, flag=cast(str, ret))
                else:
                    self.info(
                        "Checker [{}] did not return a string, assuming Mumble".format(
                            method
                        )
                    )
                    return CheckerResult(CheckerTaskResult.MUMBLE)

            if ret is not None:
                if type(ret) == str and method == CheckerMethod.PUTFLAG:
                    self.info(
                        "Checker [{}] executed successfully and returned attack info: {}".format(
                            method, ret
                        )
                    )
                    return CheckerResult(
                        CheckerTaskResult.OK, attack_info=cast(str, ret)
                    )
                else:
                    warnings.warn(
                        "Returning a result is not recommended and will be removed in the future. Raise EnoExceptions with additional text instead.",
                        DeprecationWarning,
                    )
                    try:
                        CheckerTaskResult(ret)
                    except:
                        self.error(
                            "Illegal return value from {}: {}".format(self.method, ret)
                        )
                        return CheckerResult(CheckerTaskResult.INTERNAL_ERROR)

                    ret = CheckerTaskResult(ret)
                    self.info(
                        "Checker [{}] resulted in {}".format(self.method, ret.name)
                    )
                    return CheckerResult(ret)

            # Returned Normally
            self.info("Checker [{}] executed successfully!".format(self.method))
            return CheckerResult(CheckerTaskResult.OK)

        except EnoException as eno:
            stacktrace = "".join(
                traceback.format_exception(None, eno, eno.__traceback__)
            )
            self.info(
                "Checker[{}] result: {}({})".format(
                    self.method, eno.result.name, stacktrace
                ),
                exc_info=eno,
            )

            if eno.message_contains(self.flag):
                self.error(f"EnoMessage contained flag! (Exception was {eno}")
                eno.message = None
            if eno.internal_message:
                self.info(f"Internal info for return: {eno.internal_message}")

            return CheckerResult.from_exception(eno)
        except self.requests.HTTPError as ex:
            self.info("Service returned HTTP Errorcode [{}].".format(ex), exc_info=ex)
            return CheckerResult(
                CheckerTaskResult.MUMBLE,
                "Service returned HTTP Error",
            )
        except EOFError as ex:
            self.info("Service returned EOF error [{}].".format(ex), exc_info=ex)
            return CheckerResult(
                CheckerTaskResult.MUMBLE,
                "Service returned EOF while reading response.",
            )
        except (
            self.requests.ConnectionError,  # requests
            self.requests.exceptions.ConnectTimeout,  # requests
            TimeoutError,
            socket.timeout,
            ConnectionError,
            OSError,
            ConnectionAbortedError,
        ) as ex:
            self.info(
                "Error in connection to service occurred: {}\n".format(ex), exc_info=ex
            )
            return CheckerResult(
                CheckerTaskResult.OFFLINE,
                message="Error in connection to service occured",
            )  # , ex.message
        except Exception as ex:
            stacktrace = "".join(traceback.format_exception(None, ex, ex.__traceback__))
            self.error(
                "Unhandled checker error occurred: {}\n".format(stacktrace), exc_info=ex
            )
            return CheckerResult.from_exception(ex)  # , ex.message
        finally:
            for db in self._active_dbs.values():
                # A bit of cleanup :)
                db.persist()

    @abstractmethod
    def putflag(self) -> Optional[str]:
        """
        Store a flag in the service.

        In case multiple flags are provided, self.variant_id gives the appropriate flag store to target.
        The flag itself can be retrieved from self.flag.
        On error, raise an Eno Exception.

        :return: An optional attack info string that will be publicly available to help in exploits (e.g. the username of the user to attack)
        :raises: EnoException on error
        """
        pass

    @abstractmethod
    def getflag(self) -> None:
        """
        Retrieve a flag from the service.

        Use self.flag to get the flag that needs to be recovered and self.task_chain_id as a key to retrieve data from the database stored during putflag
        On error, raise an EnoException.

        :raises: EnoException on error
        """
        pass

    @abstractmethod
    def putnoise(self) -> None:
        """
        Store noise in the service.

        The noise should later be recoverable.
        The difference between noise and flag is that noise does not have to remain secret for other teams.
        This method can be called multiple times per round. Check which variant is called using self.variant_id.
        On error, raise an EnoException.

        :raises: EnoException on error
        """
        pass

    @abstractmethod
    def getnoise(self) -> None:
        """
        Retrieve noise in the service.

        The noise to be retrieved, can be restored from the database by using the self.task_chain_id used to store it during putflag.
        The difference between noise and flag is, tht noise does not have to remain secret for other teams.
        This method can be called many times per round. Check which variant is called using self.variant_id.
        On error, raise an EnoException.

        :raises: EnoException on error
        """
        pass

    @abstractmethod
    def havoc(self) -> None:
        """
        Unleash havoc on the app -> Do whatever you must to prove the service still works. Or not.

        On error, raise an EnoException.

        :raises: EnoException on Error
        """
        pass

    @abstractmethod
    def exploit(self) -> str:
        """
        Use this method strictly for testing purposes.

        Will hopefully not be called during the actual CTF.

        :return: The flag found during the execution of this exploit
        :raises: EnoException on Error or if the flag was not found
        """
        pass

    def search_flag(self, data: str) -> Optional[str]:
        """
        Search for the flag in the input data using the flag_regex and flag_hash.

        Used only in the exploit method.

        :return: The flag if it was found, None otherwise
        """
        for flag in self._flag_regex.findall(data):
            hash_ = hashlib.sha256(flag.encode()).hexdigest()
            if hash_ == self.flag_hash:
                return flag
        return None

    def search_flag_bytes(self, data: bytes) -> Optional[str]:
        """
        Search for the flag in the input data using the flag_regex and flag_hash, where flag_regex is interpreted as binary regular expression.

        Used only in the exploit method.

        :return: The flag if it was found, None otherwise
        """
        for flag in self._flag_regex_bytes.findall(data):
            hash_ = hashlib.sha256(flag).hexdigest()
            if hash_ == self.flag_hash:
                return flag.decode()
        return None

    # ---- DB specific methods ---- #
    def db(
        self, name: str, ignore_locks: bool = False
    ) -> Union[NoSqlDict, StoredDict]:  # TODO: use a common supertype for all backends
        """
        Get a (global) db by name.

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
                port = os.getenv("MONGO_PORT")
                username = os.getenv("MONGO_USER")
                password = os.getenv("MONGO_PASSWORD")
                self.debug(
                    "Using NoSqlDict mongo://{}:{}@{}:{}".format(
                        username,
                        "".join(["X" for c in password]) if password else "None",
                        host,
                        port,
                    )
                )

                ret: Union[NoSqlDict, StoredDict] = NoSqlDict(
                    name=name,
                    checker_name=checker_name,
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    logger=self.logger,
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
    def global_db(
        self,
    ) -> Union[NoSqlDict, StoredDict]:  # TODO: use a common supertype for all backends
        """
        Get a global storage shared between all teams and rounds.

        Subsequent calls will return the same db.
        Prefer db_team_local or db_round_local

        :return: The global db
        """
        return self.db("global")

    @property
    def team_db(
        self,
    ) -> Union[NoSqlDict, StoredDict]:  # TODO: use a common supertype for all backends
        """
        Return the database for the current team.

        :return: The team local db
        """
        return self.get_team_db()

    def get_team_db(
        self, team_id: Optional[int] = None
    ) -> Union[NoSqlDict, StoredDict]:  # TODO: use a common supertype for all backends
        """
        Return the database for a specific team.

        Subsequent calls will return the same db.

        :param team: Return a db for an other team. If none, the db for the local team will be returned.
        :return: The team local db
        """
        team = team_id if team_id is not None else self.team_id
        return self.db("team_{}".format(team), ignore_locks=True)

    # ---- Networking specific methods ---- #
    def _sanitize_url(
        self, route: str, port: Optional[int] = None, scheme: Optional[str] = None
    ) -> str:
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

    def connect(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[float] = None,
        retries: int = 3,
    ) -> SimpleSocket:
        """
        Open a socket/telnet connection to the remote host.

        Use connect(..).get_socket() for the raw socket.

        :param host: the host to connect to (defaults to self.address)
        :param port: the port to connect to (defaults to self.port)
        :param timeout: timeout on connection (defaults to self.timeout)
        :param retries: the amount of times this socket connection should be retried
        :return: A connected Telnet instance
        """

        if timeout is not None:

            def timeout_fun() -> float:
                return cast(float, timeout)

        else:

            def timeout_fun() -> float:
                return self.time_remaining / 2

        if port is None:
            port = self.port
        if host is None:
            host = self.address

        if retries < 0:
            raise ValueError("Number of retries must be greater than zero.")

        for i in range(0, retries + 1):  # + 1 for the initial try
            try:

                timeout = timeout_fun()
                self.debug(
                    "Opening socket to {}:{} (timeout {} secs).".format(
                        host, port, timeout
                    )
                )
                return SimpleSocket(
                    host,
                    port,
                    timeout=timeout,
                    logger=self.logger,
                    timeout_fun=timeout_fun,
                )

            except Exception as e:
                self.warning(
                    f"Failed to establish connection to {host}:{port}, Try #{i+1} of {retries+1} ",
                    exc_info=e,
                )
                continue

        self.error(f"Failed to establish connection to {host}:{port}")
        raise OfflineException("Failed establishing connection to service.")

    @property
    def http_useragent(self) -> str:
        """
        Return the useragent for http(s) requests.

        :return: the current useragent
        """
        return self.http_session.headers["User-Agent"]

    @http_useragent.setter
    def http_useragent(self, useragent: str) -> None:
        """
        Set the useragent for http requests.

        Randomize using http_useragent_randomize()

        :param useragent: the useragent
        """
        self.http_session.headers["User-Agent"] = useragent

    def http_useragent_randomize(self) -> str:
        """
        Choose a new random http useragent.

        Note that http requests will be initialized with a random user agent already.
        To retrieve a random useragent without setting it, use random instead.

        :return: the new useragent
        """
        new_agent = random_useragent()
        self.http_useragent = new_agent
        return new_agent

    def http_post(
        self,
        route: str = "/",
        params: Any = None,
        port: Optional[int] = None,
        scheme: str = "http",
        raise_http_errors: bool = False,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> "requests.Response":
        """
        Perform a (http) requests.post to the current host.

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
        route: str = "/",
        params: Any = None,
        port: Optional[int] = None,
        scheme: str = "http",
        raise_http_errors: bool = False,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> "requests.Response":
        """
        Perform a (http) requests.get to the current host.

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
        method: str,
        route: str = "/",
        params: Any = None,
        port: Optional[int] = None,
        scheme: str = "http",
        raise_http_errors: bool = False,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> "requests.Response":
        """
        Perform an http request (requests lib) to the current host.

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


def run(
    checker_cls: Type[BaseChecker],
    args: Optional[Sequence[str]] = None,
) -> Optional[CheckerResult]:
    """
    Run a checker, either from cmdline or as uwsgi script.

    :param checker: The checker (subclass of basechecker) to run
    :param force_service: if True (non-default), the server will skip arg parsing and immediately spawn the web service.
    :param args: optional parameter, providing parameters
    :return:  Never returns.
    """
    parsed = parse_args(args)
    if parsed.runmode == "listen":
        flask_app = init_service(
            checker_cls, disable_json_logging=parsed.disable_json_logging
        )
        flask_app.run(host="::", debug=True, port=parsed.listen_port)
        return None
    else:
        task_message = task_message_from_namespace(parsed)
        result = checker_cls(
            task_message, json_logging=(not parsed.disable_json_logging)
        ).run()
        print(f"Checker run resulted in Result: {result.result.name}")
        return result
