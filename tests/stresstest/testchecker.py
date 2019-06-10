from enochecker import BaseChecker, BrokenServiceException, run, OfflineException
from enochecker.utils import *
from enochecker.storeddict import DB_DEFAULT_DIR, StoredDict
import time
import asyncio

class TestChecker(BaseChecker):
    port = 9012

    def __init__(self, *args, **kwargs):
        super(TestChecker, self).__init__(*args, **kwargs)
        
        # print(list(self.global_db.keys()))
        # if not 'bc_priv_keys' in list(self.global_db.keys()):
        #     privkeys = {5 : [], 17: [], 257:[], 65537:[]}
        #     pubkeys = {5 : [], 17: [], 257:[], 65537:[]}
        #     os.mkdir("pubkeys")
        #     for i in [5,17, 257, 65537]:
        #         os.mkdir(f"pubkeys/{str(i)}")
        #         for j in range(BC_NUMBER_OF_KEYS):
        #             key = RSA.generate(2048, e=i)
        #             pubkey = key.publickey().exportKey()
        #             with open(f"pubkeys/{str(i)}/{str(j)}", "wb") as pubf:
        #                 pubf.write(pubkey)
        #                 pubf.close()
        #             pubkeys[i].append(pubkey.decode("UTF-8"))
        #             privkeys[i].append(key.exportKey().decode("UTF-8"))

        #             # with open(f"privkeys/{str(i)}/{str(j)}", "wb") as privf:
        #             #     privf.write(key.publickey().exportKey())
        #             #     privf.close()
            
        #     self.global_db['bc_priv_keys'] = privkeys
        #     self.global_db['bc_pub_keys'] = pubkeys

    async def putflag(self):  # type: () -> None
        # with open(f"log_run_{self.round}.log", "a") as f:
        #     f.write("PUTFLAG: " + str(time.time()) + "\n")
        #     f.close()
        #self.info("WAITING")
        await asyncio.sleep(10)
        #self.info("STOPPED WAITING")
        #self.team_db[(self.flag)] = {'FLAG' : self.flag}

        
    async def getflag(self):  # type: () -> None
        # with open(f"log_run_{self.round}.log", "a") as f:
        #     f.write("GETFLAG: " +  str(time.time()) + "\n")
        #     f.close()
        await asyncio.sleep(10)
        #flagstuff = self.team_db[(self.flag)]

        
    async def putnoise(self):
        # with open(f"log_run_{self.round}.log", "a") as f:
        #     f.write("PUTNOISE: " +  str(time.time()) + "\n")
        #     f.close()
        await asyncio.sleep(10)

    async def getnoise(self):
        # with open(f"log_run_{self.round}.log", "a") as f:
        #     f.write("GETNOISE: " +  str(time.time()) + "\n")
        #     f.close()
        await asyncio.sleep(10)

    async def havoc(self):            
        # with open(f"log_run_{self.round}.log", "a") as f:
        #     f.write("HAVOC: " + str(time.time()) + "\n")
        #     f.close()
        await asyncio.sleep(10)

    async def exploit(self):
        # with open(f"log_run_{self.round}.log", "a") as f:
        #     f.write("EXPLOIT: " + str(time.time()) + "\n")
        #     f.close()
        await asyncio.sleep(10)    

app = TestChecker.service
if __name__ == "__main__":
    run(TestChecker)