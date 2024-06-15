from flask import request
import os
import hashlib


def get_flag():
    base_flag = os.getenv('FLAG', 'flag{REDACTED_[RANDOM]}')
    return base_flag.replace('[RANDOM]', 'f5e70da0')