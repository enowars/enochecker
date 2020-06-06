"""Backend for team_db based on MongoDB."""

import logging
from collections.abc import MutableMapping
from functools import wraps
from threading import RLock, current_thread
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional, Union

from . import utils
from .utils import base64ify

if TYPE_CHECKING:
    # We do these things as late as possible to avoid strange deadlocks when forking in UWSGI
    from pymongo import MongoClient

# LOGGING SETUP
logging.basicConfig(level=logging.DEBUG)
dictlogger = logging.Logger(__name__)
dictlogger.setLevel(logging.DEBUG)

RETRY_COUNT = 4

# DB DEFAULT PARAMS
DB_DEFAULT_USER = None
DB_DEFAULT_PASS = None
DB_DEFAULT_HOST = "localhost"
DB_DEFAULT_PORT = 27017


def to_keyfmt(key: Any) -> str:
    """
    Convert a string to a key used in the MongoDB.

    Currently this only returns the string representation of the key.

    :param key: the key to format
    :return: string representation of the key
    """
    return str(key)  # + type(key).__name__


def _try_n_times(func):
    @wraps(func)
    def try_n_times(*args, **kwargs):
        from pymongo.errors import PyMongoError

        for i in range(RETRY_COUNT):
            try:
                return func(*args, **kwargs)
            except PyMongoError as ex:
                dictlogger.error("noSQLdict_Error, Try {}".format(str(i)), exc_info=ex)
                if i == RETRY_COUNT:
                    raise

    return try_n_times


class NoSqlDict(MutableMapping):
    """A dictionary that is MongoDb backed."""

    dblock = RLock()

    @classmethod
    def get_client(
        cls, host: str, port: int, username: Optional[str], password: Optional[str]
    ) -> "MongoClient":
        """
        Lazily try to get the mongo db connection or creates a new one.

        :param host: mongo host
        :param port: mongo port
        :param username: the username to connect to
        :param password: the password to use
        :return:
        """
        mongo_name = utils.ensure_valid_filename(
            "mongo_{}_{}_{}_{}".format(host, port, username, password)
        )
        if hasattr(cls, mongo_name):
            return getattr(cls, mongo_name)

        from pymongo import MongoClient

        with NoSqlDict.dblock:
            if hasattr(cls, mongo_name):
                # we found a mongo in the meantime
                return getattr(cls, mongo_name)
            mongo = MongoClient(
                host=host, port=port, username=username, password=password
            )
            setattr(cls, mongo_name, mongo)
        dictlogger.debug(
            "MONGO CLIENT INITIALIZED for thread {}: {}".format(current_thread(), mongo)
        )
        return mongo

    def __init__(
        self,
        name: str = "default",
        checker_name: str = "BaseChecker",
        host: Optional[str] = None,
        port: Union[int, str, None] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        *args,
        **kwargs
    ):
        """
        Initialize a NoSqlDict with specified MongoDB backend.

        :param name: name of the backend
        :param checker_name: name of the checker
        :param host: MongoDB host
        :param port: MongoDB port
        :param username: MongoDB username
        :param password: MongoDB password
        """
        self.dict_name = base64ify(name, altchars=b"-_")
        self.checker_name = checker_name
        self.cache: Dict[Any, Any] = {}
        host_: str = host or DB_DEFAULT_HOST
        if isinstance(port, int):
            port_: int = port
        else:
            port_ = int(port or DB_DEFAULT_PORT)
        username_: Optional[str] = username or DB_DEFAULT_USER
        password_: Optional[str] = password or DB_DEFAULT_PASS
        self.db = self.get_client(host_, port_, username_, password_)[checker_name][
            self.dict_name
        ]
        try:
            self.db.index_information()["checker_key"]
        except KeyError:
            self.db.create_index(
                [("key", 1)], name="checker_key", unique=True, background=True
            )

    @_try_n_times
    def __setitem__(self, key: Any, value: Any) -> None:
        """
        Set an entry in the dictionary.

        Caches the value for future gets and stores it in the MongoDB.

        :param key: key in the dictionary
        :param value: value in the dictionary
        """
        self.cache[key] = value

        query_dict = {
            "key": to_keyfmt(key),
            "checker": self.checker_name,
            "name": self.dict_name,
        }

        to_insert = {
            "key": to_keyfmt(key),
            "checker": self.checker_name,
            "name": self.dict_name,
            "value": value,
        }

        self.db.replace_one(query_dict, to_insert, upsert=True)

    @_try_n_times
    def __getitem__(self, key: Any, print_result: bool = False) -> Any:
        """
        Get an entry from the dictionary.

        Returns values from cache when they were inserted in the same checker execution.

        :param key: key of the value to retrieve
        :param print_result: TODO
        :return: retrieved value
        """
        if key in self.cache.items():
            return self.cache[key]

        to_extract = {
            "key": to_keyfmt(key),
            "checker": self.checker_name,
            "name": self.dict_name,
        }

        result = self.db.find_one(to_extract)

        if print_result:
            dictlogger.debug(result)

        if result:
            self.cache[key] = result["value"]
            return result["value"]
        raise KeyError("Could not find {} in {}".format(key, self))

    @_try_n_times
    def __delitem__(self, key: Any) -> None:
        """
        Delete an entry from the dictionary.

        Also deletes the value from the cache in addition to the MongoDB backend.

        :param key: key to delete
        """
        if key in self.cache:
            del self.cache[key]

        to_extract = {
            "key": to_keyfmt(key),
            "checker": self.checker_name,
            "name": self.dict_name,
        }
        self.db.delete_one(to_extract)

    @_try_n_times
    def __len__(self) -> int:
        """
        Return the number of elements in the dictionary.

        :return: number of elements
        """
        return self.db.count_documents(
            {"checker": self.checker_name, "name": self.dict_name}
        )

    @_try_n_times
    def __iter__(self) -> Iterable[Any]:
        """
        Return an iterator over all entries in the dictionary.

        :return: iterator over the entries
        """
        iterdict = {"checker": self.checker_name, "name": self.dict_name}
        results = self.db.find(iterdict)
        yield from map(lambda res: res["key"], results)

    def persist(self) -> None:
        """
        Persist the changes in the backend.

        Currently this function does nothing since every access queries the database already.
        In the future changes to the DB might be cached until they are explicitly persisted.
        """
        # TODO: could wait until here before hitting the mongodb...
        pass
