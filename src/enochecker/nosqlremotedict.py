
import collections
#import logging
from pymongo import MongoClient
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
DB_DEFAULT_PORT = 2701


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

        self.db = self.client.checkerdata['checker_name']
        # ADD CACHING MECHANISM?

    def __setitem__(self, key, value):

        to_insert = {
            "key":      key,
            "checker":  self.dict_name,
            "name":     self.name,
            "value":    value
            }

        self.db.insert_one(to_insert)
    
    def __getitem__(self, key):

        to_extract = {
            "key":      key,
            "checker":  self.dict_name,
            "name":     self.name
            }

        result = self.db.find_one(to_extract)

        if result:
            return result['value']
        raise KeyError()

    def __delitem__(self, key):
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
        pass