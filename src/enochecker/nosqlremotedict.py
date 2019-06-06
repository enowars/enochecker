
import collections
#import logging
from pymongo import MongoClient, HASHED
#from urllib.parse import quote_plus

# LOGGING SETUP
#logging.basicConfig(level=logging.DEBUG)
#dictlogger = logging.Logger(__name__)
#dictlogger.setLevel(logging.DEBUG)

# DIR
DB_DEFAULT_DIR = None
DB_GLOBAL_CACHE_SETTING = False

# DB DEFAULT PARAMS
DB_DEFAULT_USER = 'root'
DB_DEFAULT_PASS = 'example'
DB_DEFAULT_HOST = '172.20.0.3'
DB_DEFAULT_PORT = 27017


class StoredDict(collections.MutableMapping):
    """
    A dictionary that is MongoDb backed.
    """

    def __init__(self, checker_name="BaseChecker", dict_name="default",
                 host=DB_DEFAULT_HOST, port=DB_DEFAULT_PORT, 
                 username=DB_DEFAULT_USER, password=DB_DEFAULT_PASS):

        self.client = MongoClient(
            host=host,
            port=port,
            username=username,
            password=password)

        self.dict_name = dict_name
        self.name = checker_name
                            # Table by checker
        self.db = self.client[checker_name][dict_name]
                                        # Collection by team/global
        self.cache = dict()

        # Add DB index
        try:
            self.db.index_information()['checker_key']
        except KeyError:
            self.db.create_index(
                [("key", HASHED), ("checker", HASHED), ("name", HASHED)],
                name="checker_key", unique=True, background=True
                )
        
        # ADD CACHING MECHANISM?

    def __setitem__(self, key, value):

        self.cache[key] = value

        query_dict = {
            "key":      key,
            "checker":  self.dict_name,
            "name":     self.checker_name
            }

        to_insert = {
            "key":      key,
            "checker":  self.dict_name,
            "name":     self.checker_name,
            "value":    value
            }

        self.db.replace_one(query_dict, to_insert, upsert=True)
    
    def __getitem__(self, key):

        if key in self.cache:
            return self.cache[key]

        print('DB CALL')
        to_extract = {
            "key":      key,
            "checker":  self.dict_name,
            "name":     self.name
            }

        result = self.db.find_one(to_extract)

        if result:
            self.cache[key] = result['value']
            return result['value']
        raise KeyError()

    def __delitem__(self, key):
        
        if key in self.cache:
            del self.cache[key]

        to_extract = {
            "key":      key,
            "checker":  self.dict_name,
            "name":     self.name
            }
        self.db.delete_one(to_extract)

    def __len__(self):
        return self.db.count_documentd({})

    def __iter__(self):
        iterdict = {
            "checker":  self.dict_name,
            "name":     self.name
        }
        results = self.db.find(iterdict)
        return results

    def persist(self):
        self.cache = dict()
