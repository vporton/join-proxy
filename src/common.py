import json

from flask import Flask
from flask_compress import Compress
import lmdb
from flufl.lock import Lock

with open("config.json") as config_file:
    config = json.load(config_file)


app = Flask(__name__)
Compress(app)


class OurDB:
    def __enter__(self):
        # NFS filesystem safe lock
        self.lock = Lock(f"{config['statePath']}/mylock")
        self.lock.lock(timeout=4)  # FIXME: Ensure, it is not unlocked in the middle.

        self.env = lmdb.open(
            config['statePath'],
            max_dbs=8, map_size=1024*1024*1024*1024)  # terabyte (On 64-bit there is no penalty for making this huge (say 1TB))
        self.content_db = self.env.open_db(b'content', create=True)
        self.time_db = self.env.open_db(b'time', create=True, integerkey=True, dupsort=True)  # TODO: needs at least 64 bit integer

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.env.close()
        self.lock.unlock()
