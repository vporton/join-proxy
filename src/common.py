import json
import struct

from flask import Flask
from flask_compress import Compress
import lmdb
from flufl.lock import Lock

with open("config.json") as config_file:
    config = json.load(config_file)


app = Flask(__name__)
# Compress(app)


class OurDB:
    def __enter__(self):
        # NFS filesystem safe lock
        self.lock = Lock(f"{config['statePath']}/mylock")
        self.lock.lock(timeout=4)  # FIXME: Ensure, it is not unlocked in the middle.

        self.env = lmdb.open(config['statePath'], max_dbs=10, map_size=200*1024*1024*1024)
        self.accounts_db = self.env.open_db(b'accounts', create=True)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.env.close()
        self.lock.unlock()

    # TODO: Reimplement in Rust, because other backend parts may also require to check this.
    # Format of records:
    # (float balance,) - paid
    # (float balance,int8 end) - trial period ends at `end` seconds since UTC epoch
    # @staticmethod
    # def accounts_pack(info):
    #     if info[1] is not None:
    #         return struct.pack('<fq', info)
    #     else:
    #         return struct.pack('<f', info[0])
    #
    # @staticmethod
    # def accounts_unpack(data):
    #     try:
    #         balance, = struct.unpack('<f', data)
    #         return balance, None
    #     except struct.error:
    #         return struct.unpack('<fq', data)

def fund_account(our_db, account, amount):
    with our_db.env.begin(our_db.accounts_db, write=True) as txn:  # TODO: buffers=True allowed?
        remainder = txn.get(account)
        if remainder is None:
            remainder = 0.0
        else:
            remainder = struct.unpack('<f', remainder)[0]  # float
        txn.put(account, struct.pack('<f', remainder + amount))
