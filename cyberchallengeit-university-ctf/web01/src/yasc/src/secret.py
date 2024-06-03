import os

def get_flag():
    base_flag = os.getenv('FLAG', 'CCIT{REDACTED_[RANDOM]}')
    return base_flag.replace('[RANDOM]', '3962fd46')
