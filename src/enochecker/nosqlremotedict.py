
import collections
#import logging
from pymongo import MongoClient
from urllib.parse import quote_plus

# LOGGING SETUP
#logging.basicConfig(level=logging.DEBUG)
#dictlogger = logging.Logger(__name__)
#dictlogger.setLevel(logging.DEBUG)

# DB Host JUST TESTING
db_user = 'root'
db_passw = 'example'
db_host = '172.20.0.3'
db_port = 2701


class NoSqlStoredDict(collections.MutableMapping):
    """
    A dictionary that is MongoDb backed.
    """

    def __init__(self):
        self.client = MongoClient(host = db_host, username = db_user, password = db_passw)
        self.db = self.client.checkerdata.collection

    def __setitem__(self, key, value):
        to_insert = {"key" : key, "value":value}
        self.db.insert_one(to_insert)
    
    def __getitem__(self, key):
        result = self.db.find_one({"key":key})
        if result:
            return result['value']
        return None ## raise Exception ?

    def __delitem__(self, key):
        self.db.delete_one({"key" : key})
    
    def __len__(self):
        return self.db.count_documentd({})
    
    def __iter__(self):
        return None