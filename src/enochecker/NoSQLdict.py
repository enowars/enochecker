import atexit
import collections
import json
import os
import logging
from pymongo import MongoClient

from .utils import ensure_valid_filename, base64ify, debase64ify, start_daemon


# DATABASE SETUP
DB_DEFAULT_URL = 'mongodb://localhost:8081/'

def to_keyformat(key) -> str:
    return str((str(key), type(key)))

# Logger setup

logging.basicConfig(level=logging.DEBUG)
dictlogger = logging.Logger(__name__)
dictlogger.setLevel(logging.DEBUG)


# class RemoteData(Base):
#     __tablename__ = 'checkerdata'

#     id = Base.Column(Base.Integer, primary_key=True)
#     checker = Base.Column(Base.Integer, primary_key=True)
#     team = Base.Column(Base.Integer())
#     key = Base.Column(Base.String())
#     data = Base.Column(Base.JSON)


class StoredDict(collections.MutableMapping):
    """
    A dictionary that is filesystem backed.
    It will write to disk every few seconds and at exit.
    In case python crashes, changes may be gone. :/
    Note: Complex won't be tracked.
    """

    def __init__(self, base_path=DB_DEFAULT_URL, name="default",
                 persist_secs=3, ignore_locks: bool = False, logger=None) -> None:
        # type: (str, str, int, bool, Optional[logging.Logger]) -> None
        """
        Creates a new File System backed Store.
        It quacks like a dict and will persist to filesystem every few seconds if possible. :)
        :param base_path: the base path : int 
        :param name: name of this store
        :param persist_secs: how often to persist dirty elements (0 means: never autostore. Call persist manually)
        :param ignore_locks: We usually write and read lock files before accessing the data.
                This flag seaves them out.
        :param logger: The logger instance to log events to
        """
        self.client = MongoClient(DB_DEFAULT_URL)
        self.db = self.client['checkerdata']
        self.collection = self.db[name]

        self.name = name
        # self.ignore_locks = ignore_locks  # type: bool

        if logger:
            self.logger = logger
        else:
            self.logger = dictlogger

        self.__cache = {}
        # atexit.register(self._cleanup)
        # self._stopping = False

    def _cleanup(self):
        # type: () -> None
        """Cleans up the db: persists and releases all locks currently held."""
        self.logger.debug("StoredDict cleanup task running.")
        self._stopping = True
        self.persist()

    def __del__(self):
        # type: () -> None
        """
        Delete a key
        """
        self._cleanup()

    def persist(self):
        # type: () -> None
        """
        Stores all dirty data to disk.
        If no data is to be stored, it's basically free to call.
        """
        for key in self._to_delete:
            locked = self.is_locked(key) or self.ignore_locks
            if not locked:
                self.lock(key)
            os.remove(self._dir_jsonname(key))
            if not locked:
                self.release(key)
        self._to_delete = set()

        for key in self._dirties:
            locked = self.is_locked(key)
            if not locked:
                self.lock(key)
            try:
                with open(self._dir_jsonname(key), "wb") as f:
                    f.write(json.dumps(self._cache[key]).encode("utf-8"))
            finally:
                if not locked:
                    self.release(key)
        self._dirties = set()

    def __getitem__(self, key):

        if key in self._cache:
            self.logger.log(logging.INFO, f"Trying to get item: {str}, retrieving from cache")
            return self._cache[str(key)]
        
        querydict = {
            "key" : to_keyformat(key),
        }


        # Remote Access:
        data = self.collection.find({,"key": to_keyformat(key)})['data']
        if data is None:
            raise KeyError

        self._cache[str(key)] = data
        return data

    def __setitem__(self, key, value):
        # type: (str, Any) -> None
        """
        Set an item. It'll be stored to disk on the next persist.
        :param key: Key to store
        :param value: Value to store
        """
        self._to_delete.remove(key)
        self._cache[key] = value
        self._dirties.add(key)

    def __delitem__(self, key):
        # type: (str) -> None
        """
        Delete an item. It will be deleted from disk on the next .persist().
        :param key: the key to delete
        """
        self._to_delete.add(key)

    def __iter__(self):
        # type: () -> Iterator[(str, Any)]
        """
        Iterates over the dict. Implicitly persisting the data before reading.
        :return: An iterator containing all keys to a dict.
        """
        self.persist()
        keys = [debase64ify(x[len(DB_PREFIX):-len(DB_EXTENSION)]) for x in os.listdir(self.path) if
                x.startswith(DB_PREFIX) and x.endswith(DB_EXTENSION)]
        for key in keys:
            yield key

    def __len__(self):
        # type: () -> int
        """
        Calculates the length. Implicitly calls persist.
        :return: the the number of elements
        """
        self.persist()
        keys = [x[len(DB_PREFIX):-len(DB_EXTENSION)] for x in os.listdir(self.path) if
                x.startswith(DB_PREFIX) and x.endswith(DB_EXTENSION)]
        return len(keys)
