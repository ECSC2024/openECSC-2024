import hashlib
import os

def flag():
    return os.getenv("FLAG").format(hashlib.sha1(os.urandom(8)).hexdigest()[:8])