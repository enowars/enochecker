"""Backend for team_db based on a local filesystem directory."""

import atexit
import json
import logging
import os
import threading
import time
from collections.abc import MutableMapping
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, Set

from .utils import base64ify, debase64ify, ensure_valid_filename, start_daemon

logging.basicConfig(level=logging.DEBUG)
dictlogger = logging.Logger(__name__)
dictlogger.setLevel(logging.DEBUG)

DB_DEFAULT_DIR = os.path.join(
    os.getcwd(), ".data"
)  # Default location db files will be stored in -> usually cwd.
# TODO: Force remove locks after a while?
DB_LOCK_RETRYCOUNT = (
    6  # 2**6 / 10 seconds are 6.4 secs. -> That's how long the db will wait for a log
)
DB_PREFIX = "_store_"  # Prefix all db files will get
DB_EXTENSION = ".json"  # Extension all db files will get
DB_LOCK_EXTENSION = ".lock"  # Extension all lock folders will get
DB_GLOBAL_CACHE_SETTING = True


def makedirs(path: str, exist_ok: bool = True) -> None:
    """
    Create a directory.

    Creates the parent directories if necessary.

    param path: the path to create
    param exist_ok: ignore already existing path and do nothing
    """
    Path(path).mkdir(parents=True, exist_ok=exist_ok)


def _locked(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Return a wrapped method for StoredDict accesses to ensure locks on a python threading level.

    :param func: StoredDict method to be wrapped
    :return: the wrapped method
    """

    @wraps(func)
    def locked(self: "StoredDict", *args: str, **kwargs: int) -> Callable[..., Any]:
        """
        Wrap the function.

        First acquires a lock and then releases it later.

        :param args: positional arguments passed to the wrapped function
        :param kwargs: kwargs to pass to the wrapped function
        :return: the wrapped function
        """
        self.logger.debug("Locking {} db".format(self.name))
        self._local_lock.acquire()
        self.logger.debug("Log db lock for {}".format(self.name))
        try:
            return func(self, *args, **kwargs)
        finally:
            self._local_lock.release()
            self.logger.debug("Released db lock for {}".format(self.name))

    return locked


class StoredDict(MutableMapping):
    """
    A dictionary that is filesystem backed.

    It will write to disk every few seconds and at exit.
    In case python crashes, changes may be gone. :/
    Note: Complex won't be tracked.
    """

    def __init__(
        self,
        name: str = "default",
        base_path: str = DB_DEFAULT_DIR,
        persist_secs: int = 3,
        ignore_locks: bool = False,
        logger: Optional[logging.Logger] = None,
        *args,
        **kwargs
    ) -> None:
        """
        Create a new File System backed Store.

        It quacks like a dict and will persist to filesystem every few seconds if possible. :)

        :param name: name of this store
        :param base_path: the base path
        :param persist_secs: how often to persist dirty elements (0 means: never autostore. Call persist manually)
        :param ignore_locks: We usually write and read lock files before accessing the data.
                This flag seaves them out.
        :param logger: The logger instance to log events to
        """
        self._cache: Dict[str, Any] = {}
        self._dirties: Set[str] = set()
        self._locks: Set[str] = set()
        self._to_delete: Set[str] = set()
        self._persist_thread: Optional[threading.Thread] = None
        self.name = name
        self.path: str = os.path.join(base_path, ensure_valid_filename(name))
        self.persist_secs: int = persist_secs
        self.ignore_locks: bool = ignore_locks

        if logger:
            self.logger = logger
        else:
            self.logger = dictlogger

        self._local_lock = threading.RLock()

        makedirs(self.path, exist_ok=True)
        atexit.register(self._cleanup)
        self._stopping = False

        self.update(
            dict(*args, **kwargs)
        )  # In case we got initialized using a dict, make sure it's in sync.

    @_locked
    def _spawn_persist_thread(self) -> None:
        """Spawn a thread persisting all changes, if necessary."""
        if self.persist_secs > 0 and not self._persist_thread:

            def persist_async():
                time.sleep(self.persist_secs)
                self.logger.debug("Persisting db {} from background.".format(self.name))
                self.persist()

            self._persist_thread = start_daemon(persist_async)

    @_locked
    def _cleanup(self) -> None:
        """Clean up the db: persists and releases all locks currently held."""
        self.logger.debug("StoredDict cleanup task running.")
        self._stopping = True
        self.persist()
        for lock in self._locks:
            self.release(lock)

    def __del__(self) -> None:
        """Delete a key."""
        self._cleanup()

    def _dir(self, key: str) -> str:
        """
        Return the path where data for this key is stored.

        :param key: the key to look up
        :return: string representation of the file path
        """
        return os.path.join(self.path, DB_PREFIX + base64ify(key, b"+-"))

    def _dir_jsonname(self, key: str) -> str:
        """
        Return the path for the json db file for this key.

        See :func:`_dir`
        """
        return "{}{}".format(self._dir(key), DB_EXTENSION)

    def _dir_lockname(self, key: str) -> str:
        """
        Return the path for the lock file for this key.

        See :func:`_dir`
        """
        return "{}{}".format(self._dir(key), DB_LOCK_EXTENSION)

    @_locked
    def release(self, locked_key: str) -> None:
        """
        Release a file lock.

        :param locked_key: the key we locked
        """
        if locked_key not in self._locks:
            raise KeyError("{} was not locked.".format(locked_key))
        self._dir_lockname(locked_key)
        os.rmdir(self._dir_lockname(locked_key))
        self._locks.remove(locked_key)

    @_locked
    def mark_dirty(self, key: str) -> Any:
        """
        Manually mark an entry as dirty. It will be updated on disk on the next occasion.

        :param key: the key that needs to be stored
        :return: the value contained in the key
        """
        val = self[key]
        self[key] = val
        return val

    def _create_lock_file(
        self, path: str, retrycount: int = DB_LOCK_RETRYCOUNT
    ) -> None:
        """
        Create new lock file, waiting up to retrycount seconds.

        :raises: :class:`TimeoutError` if failed.
        :param path: path of the lock file
        :param retrycount: number of tries until raising an Exception
        """
        for i in range(0, retrycount):
            try:
                makedirs(path, exist_ok=False)
                return
            except OSError as ex:
                self.logger.debug(
                    "Waiting for lock on file {} (currently {})".format(path, ex)
                )
                time.sleep(float(2 ** i) / 10)
        raise TimeoutError("Lock for {} could not be acquired in time!".format(path))

    @_locked
    def lock(self, key: str) -> None:
        """
        Wait for a lock.

        :param key: the key to lock
        """
        if key in self._locks:
            raise KeyError("{} already locked".format(key))
        self._create_lock_file(self._dir_lockname(key))
        self._locks.add(key)

    @_locked
    def is_locked(self, key: str) -> bool:
        """
        Return if the key is currently locked by this process.

        :param key: The key
        :return: True if locked by this process, False otherwise
        """
        return key in self._locks

    @_locked
    def reload(self) -> None:
        """
        Reload stored values from disk.

        There is usually no reason to call this.
        Non persisted changes might be lost.
        Only reason would be if another process fiddles with our data concurrently.
        """
        self._cache = {}
        self._dirties = set()
        self._to_delete = set()

    @_locked
    def persist(self) -> None:
        """
        Store all dirty data to disk.

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

    @_locked
    def __getitem__(self, key: str) -> Any:
        """
        Get an item from the dict. Will hit the cache first, then disk.

        :param key: the key to look up
        :return: the value
        """
        if key in self._to_delete:
            raise KeyError("Key was marked for deletion: {}".format(key))
        try:
            return self._cache[key]
        except KeyError:
            self.logger.debug("Hitting disk for {}".format(key))

        locked = self.is_locked(key) or self.ignore_locks
        if not locked:
            self.lock(key)
        try:
            with open(self._dir_jsonname(key), "rb") as f:
                val = json.loads(f.read().decode("utf-8"))
        except OSError as ex:
            raise KeyError("Key {} not found - {}".format(key, ex))
        finally:
            if not locked:
                self.release(key)

        self._cache[key] = val
        return val

    @_locked
    def __setitem__(self, key: str, value: Any) -> None:
        """
        Set an item. It'll be stored to disk on the next persist.

        :param key: Key to store
        :param value: Value to store
        """
        if key in self._to_delete:
            self._to_delete.remove(key)
        self._cache[key] = value
        self._dirties.add(key)

    @_locked
    def __delitem__(self, key: str) -> None:
        """
        Delete an item. It will be deleted from disk on the next .persist().

        :param key: the key to delete
        """
        self._to_delete.add(key)

    def __iter__(self) -> Iterator[str]:
        """
        Return an iterator over the dict.

        Implicitly persisting the data before reading.

        :return: An iterator containing all keys to a dict.
        """
        self.persist()
        keys = [
            debase64ify(x[len(DB_PREFIX) : -len(DB_EXTENSION)], b"+-")
            for x in os.listdir(self.path)
            if x.startswith(DB_PREFIX) and x.endswith(DB_EXTENSION)
        ]
        yield from keys

    def __len__(self) -> int:
        """
        Calculate the length of the dict.

        Implicitly calls persist.

        :return: the the number of elements
        """
        self.persist()
        keys = [
            x[len(DB_PREFIX) : -len(DB_EXTENSION)]
            for x in os.listdir(self.path)
            if x.startswith(DB_PREFIX) and x.endswith(DB_EXTENSION)
        ]
        return len(keys)
