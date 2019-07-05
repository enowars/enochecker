import collections
import configparser
import os
import logging

from functools import wraps
from pymongo.errors import PyMongoError
# import logging
from pymongo import MongoClient
from .results import BrokenCheckerException
from .utils import base64ify

# from urllib.parse import quote_plus

try:
    import uwsgi
    from uwsgidecorators import postfork
except (ImportError, ModuleNotFoundError):
    def postfork(func):
        func()
        return func

# LOGGING SETUP
logging.basicConfig(level=logging.DEBUG)
dictlogger = logging.Logger(__name__)
dictlogger.setLevel(logging.DEBUG)

# DIR
DB_DEFAULT_DIR = None
DB_GLOBAL_CACHE_SETTING = False
RETRY_COUNT = 4

# DB DEFAULT PARAMS
DB_DEFAULT_USER = 'root'
DB_DEFAULT_PASS = 'example'
DB_DEFAULT_HOST = '172.20.0.3'
DB_DEFAULT_PORT = 27017

# INIT OVERRIDE
print("READING INIT")
config = configparser.ConfigParser()
config.read("db.ini")
config.read("DB.ini")
config.read("database.ini")
config.read("Database.ini")
config.read("DATABASE.ini")

if 'DATABASE' in config:
    if 'HOST' in config['DATABASE']:
        DB_DEFAULT_HOST = config['DATABASE']['HOST']
    if 'PORT' in config['DATABASE']:
        DB_DEFAULT_PORT = int(config['DATABASE']['PORT'])
    if 'USER' in config['DATABASE']:
        DB_DEFAULT_USER = config['DATABASE']['USER']
    if 'PASSWORD' in config['DATABASE']:
        DB_DEFAULT_PASS = config['DATABASE']['PASSWORD']

if 'MONGO_HOST' in os.environ:
    DB_DEFAULT_HOST = os.environ['MONGO_HOST']
if 'MONGO_PORT' in os.environ:
    DB_DEFAULT_PORT = int(os.environ['MONGO_PORT'])
if 'MONGO_USER' in os.environ:
    DB_DEFAULT_USER = os.environ['MONGO_USER']
if 'MONGO_PASSWORD' in os.environ:
    DB_DEFAULT_PASS = os.environ['MONGO_PASSWORD']

print("host = ", DB_DEFAULT_HOST)
print("port = ", DB_DEFAULT_PORT)
print("username = ", DB_DEFAULT_USER)
print("password = ", DB_DEFAULT_PASS)

global CLIENT
CLIENT = MongoClient(
    host=DB_DEFAULT_HOST,
    port=DB_DEFAULT_PORT,
    username=DB_DEFAULT_USER,
    password=DB_DEFAULT_PASS)


@postfork
def initialize_connection():
    global CLIENT
    CLIENT = MongoClient(
        host=DB_DEFAULT_HOST,
        port=DB_DEFAULT_PORT,
        username=DB_DEFAULT_USER,
        password=DB_DEFAULT_PASS)
    print("MONGO CLIENT INITIALIZED")


def to_keyfmt(key):
    return str(key)  # + type(key).__name__


def _try_n_times(func):
    @wraps(func)
    def try_n_times(*args, **kwargs):
        for i in range(RETRY_COUNT):
            try:
                return func(*args, **kwargs)
            except PyMongoError as ex:
                dictlogger.error("noSQLdict_Error, Try {}".format(str(i)), exc_info=ex)
                if i == RETRY_COUNT:
                    raise

    return try_n_times


class StoredDict(collections.MutableMapping):
    """
    A dictionary that is MongoDb backed.
    """

    def __init__(self, checker_name="BaseChecker", dict_name="default",
                 host=DB_DEFAULT_HOST, port=DB_DEFAULT_PORT,
                 username=DB_DEFAULT_USER, password=DB_DEFAULT_PASS):
        global CLIENT
        for i in range(RETRY_COUNT):
            try:
                # self.client = 
                self.dict_name = base64ify(dict_name, altchars=b"-_")
                self.checker_name = checker_name
                #                   Table by checker
                self.db = CLIENT[checker_name][self.dict_name]
                #                           Collection by team/global
                self.cache = dict()

                # Add DB index
                try:
                    self.db.index_information()['checker_key']
                except KeyError:
                    self.db.create_index(
                        [("key", 1)],
                        name="checker_key", unique=True, background=True
                    )
            except PyMongoError as ex:
                dictlogger.error("noSQLdict_Error", exc_info=ex)
                if i == RETRY_COUNT - 1:
                    raise BrokenCheckerException from ex

    @_try_n_times
    def __setitem__(self, key, value):
        self.cache[key] = value

        query_dict = {
            "key": to_keyfmt(key),
            "checker": self.checker_name,
            "name": self.dict_name
        }

        to_insert = {
            "key": to_keyfmt(key),
            "checker": self.checker_name,
            "name": self.dict_name,
            "value": value
        }

        self.db.replace_one(query_dict, to_insert, upsert=True)

    @_try_n_times
    def __getitem__(self, key, print_result=False):

        if key in self.cache:
            return self.cache[key]

        to_extract = {
            "key": to_keyfmt(key),
            "checker": self.checker_name,
            "name": self.dict_name
        }

        result = self.db.find_one(to_extract)

        if print_result:
            print(result)

        if result:
            self.cache[key] = result['value']
            return result['value']
        raise KeyError()

    @_try_n_times
    def __delitem__(self, key):

        if key in self.cache:
            del self.cache[key]

        to_extract = {
            "key": to_keyfmt(key),
            "checker": self.checker_name,
            "name": self.dict_name
        }
        self.db.delete_one(to_extract)

    @_try_n_times
    def __len__(self):

        return self.db.count_documents(
            {
                "checker": self.checker_name,
                "name": self.dict_name}
        )

    @_try_n_times
    def __iter__(self):

        iterdict = {
            "checker": self.checker_name,
            "name": self.dict_name
        }
        results = self.db.find(iterdict)
        for key in map(lambda res: res['key'], results):
            yield key

    @_try_n_times
    def persist(self):

        self.cache = dict()

    @_try_n_times
    def __del__(self):
        self.persist()
