import os


def get_flag():
    base_flag = os.getenv('FLAG', 'TeamItaly{REDACTED_%s}')
    return base_flag % 'c40b3a45'
