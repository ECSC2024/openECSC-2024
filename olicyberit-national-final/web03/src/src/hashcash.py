#!/usr/bin/env python3
"""
  ----------------------------------------------------------------------------
  "THE BEER-WARE LICENSE" (Revision 42):
  <antbob@users.noreply.github.com> wrote this file. As long as you retain
  this notice you can do whatever you want with this stuff. If we meet
  some day, and you think this stuff is worth it, you can buy me a beer in
  return Anton Bobrov
  ----------------------------------------------------------------------------
"""
"""
HashCash minting and checking implementation, see http://www.hashcash.org
for more details. This implementation does not support hashcash extensions
(ignores them) or double spend database. Based on version 1 format and has
support for arbitrary number of leading zero bits when minting or checking
and ability to pick and override hashcash date field with standard formats.
"""
import time
import struct
import base64
import random
import codecs
import hashlib
import datetime

if __name__ == '__main__':
    import argparse
    import sys
    import re

def hashcash_check(stamp, resource=None, nbits=None, etime=None, ntime=None):
    """
    Verify a hashcash stamp optionally checking for specific parameters.

    Args:
        stamp:    Hashcash stamp, format (as of version 1):
                  ver:bits:date:resource:[ext]:rand:counter.
        resource: Assert resource string (eg IP address, email address).
        nbits:    Assert the number of leading zero bits the stamp is
                  required to have.
        etime:    Expiration time to check, in seconds, default 28 days.
        ntime:    Override current or now time, system time by default,
                  supported formats: YYMMDD, YYMMDDhhmm, YYMMDDhhmmss

    Returns:
        True, if a specified stamp passes verification,
        False otherwise.

    Raises:
        AssertionError: Raises an assertion error
        if one of the parameters fails to validate.
    """

    hashcash = hashlib.sha1(stamp.encode()).digest()

    # Stamp format is ver:bits:date:resource:[ext]:rand:counter
    stamp_split = stamp.split(':')

    if resource != None and resource != stamp_split[3]:
        raise AssertionError( \
            "hashcash stamp resource does not match")

    stamp_bits = int(stamp_split[1])
    if nbits != None and stamp_bits < nbits:
        raise AssertionError( \
            "hashcash stamp has less bits than required")

    stamp_time = _parse_time_stamp(stamp_split[2])

    if ntime is None:
        now_time = time.time()
    else:
        now_time = _parse_time_stamp(ntime)

    if stamp_time > now_time:
        raise AssertionError( \
            "hashcash stamp has its date set in the future")
    else:
        if etime is None:
            # By default stamps expire in 28 days.
            etime = 2419200
        if now_time - stamp_time > etime:
            raise AssertionError( \
                "hashcash stamp has expired")

    if not check_hash_for_cash(hashcash, stamp_bits):
        return False

    return True

def hashcash_mint(resource, nbits=None, stime=None):
    """
    Mints and returns a hashcash stamp with parameters specified.

    Args:
        resource: Resource string (eg IP address, email address).
        nbits:    Number of leading zero bits the stamp must have,
                  default: 20 bits.
        stime:    Override stamp time, system time by default in
                  YYMMDDhhmmss format, supported formats: YYMMDD,
                  YYMMDDhhmm, YYMMDDhhmmss

    Returns:
        Hashcash stamp string.

    Raises:
        ValueError: Raises a value error for invalid parameters.
    """

    # Python global interpreter lock (GIL) allows only one
    # thread to execute at any given time. Since minting
    # is CPU intensive it does not make sense to make this
    # into a parallel function. The 'multiprocessing' way
    # isnt really feasible either due to high sync costs.

    if nbits is None:
        # The default is 20 bits.
        nbits = 20

    if stime is None:
        date_time = datetime.datetime.today().strftime('%y%m%d%H%M%S')
    else:
        # Valid date formats are: YYMMDD, YYMMDDhhmm, YYMMDDhhmmss
        if len(stime) == 12:
            datetime.datetime.strptime(stime, '%y%m%d%H%M%S')
        elif len(stime) == 10:
            datetime.datetime.strptime(stime, '%y%m%d%H%M')
        elif len(stime) == 6:
            datetime.datetime.strptime(stime, '%y%m%d')
        else:
            raise ValueError
        date_time = stime

    # Stamp format is ver:bits:date:resource:[ext]:rand:counter
    hashcash_header = ('1:' + str(nbits) + ':' + \
        date_time + ':' + resource + '::')

    # Base64 encoding overhead is 4:3 so to get 16 chars
    # b64 encoded value 96 bits random value is required.
    random_bits = random.getrandbits(96)
    random_bytes = struct.pack('>QL', \
        random_bits & 0xFFFFFFFFFFFFFFFF, \
        random_bits >> 64)

    # Allowed characters are from alphabet a-zA-Z0-9+/=
    # Base64 encode and strip padding to reduce noise.
    # Padding can be restored later with something like:
    # b64padded = b64 + '=' * (-len(b64) % 4)
    random_string_b64 = base64.b64encode(random_bytes)
    random_string = codecs.ascii_decode(random_string_b64)

    hashcash_header = hashcash_header + \
        random_string[0].rstrip('=') + ':'

    return mint_hash_for_cash(nbits, hashcash_header)

def mint_hash_for_cash(nbits, hcheader):
    """
    Mints and returns a hashcash stamp with pre-baked parameters.

    Args:
        nbits:    Number of leading zero bits the stamp must have.
        hcheader: Pre-baked hashcash header sans counter field eg,
                  1:20:700101:email@example.com::yPbguc1Z9xto4Yc0:

    Returns:
        Hashcash stamp string.
    """

    counter = 0
    header_bytes = hcheader.encode()

    while True:
        # Counter characters are from alphabet a-zA-Z0-9+/=
        counter_string = hex(counter)[2:]

        if check_hash_for_cash(hashlib.sha1(header_bytes + \
                counter_string.encode()).digest(), nbits):
            break
        counter = counter + 1

    return hcheader + counter_string

def check_hash_for_cash(digest_bytes, zero_bits):
    """
    Checks whether or not provided SHA1 digest has sufficient
    number of leading zero bits.

    Args:
        digest_bytes: SHA1 digest bytes to check.
        nbits:        Number of leading zero bits required.

    Returns:
        True, if provided SHA1 digest has sufficient
        number of leading zero bits, False otherwise.
    """

    bit_counter = 0

    # SHA-1 is 160-bit big endian.
    for hash_byte in digest_bytes:
        if bit_counter >= zero_bits:
            return True
        bits_remain = zero_bits - bit_counter
        if bits_remain >= 8:
            if hash_byte == 0x00:
                bit_counter = bit_counter + 8
                continue
            else:
                return False
        else:
            for bit in range(bits_remain - 1, -1, -1):
                bit_counter = bit_counter + 1
                mask = 0x80 >> bit
                if hash_byte & mask:
                    return False

    return True

def main():
    """
    Script mode main.
    """

    parser = _build_args_parser()
    args = parser.parse_args()

    if args.m:
        if args.r is None:
            parser.error("-m: requires argument -r")
        if args.e:
            parser.error("-e: not allowed with argument -m")
        sys.stdout.write("Minting hashcash stamp, this may take a while...")
        sys.stdout.flush()
        start_time = time.time()
        hashcash_stamp = hashcash_mint(args.r, args.b, args.t)
        stop_time = time.time() - start_time
        sys.stdout.write("[DONE]\n")
        sys.stdout.write("Hashcash stamp: " + hashcash_stamp + "\n")
        if args.v:
            hash_tries = int(hashcash_stamp.split(':')[-1], 16)
            sys.stdout.write("Time: " + str(stop_time) + " seconds\n")
            sys.stdout.write("Tries: " + str(hash_tries) + "\n")
            sys.stdout.write("Rate/s: %d" % (hash_tries / stop_time) + "\n")
        sys.stdout.flush()
    elif args.c:
        etime = 0
        if args.e:
            etime_match = re.match(r'^(\d+)\s*([s|m|h|d])', args.e)
            if etime_match:
                duration = etime_match.group(1)
                unit = etime_match.group(2)
                unit_mapper = {
                    's': '*1',
                    'm': '*60',
                    'h': '*60*60',
                    'd': '*60*60*24',
                }
                expression = duration + unit_mapper.get(unit)
                # ast.literal_eval cannot be used here,
                # see http://bugs.python.org/issue22525
                etime = eval(expression) # pylint: disable=eval-used
            else:
                parser.error("-e: failed to parse value")
        try:
            stamp_is_valid = hashcash_check(args.c, args.r, args.b, \
                int(etime) if args.e else None, args.t)
            if stamp_is_valid:
                sys.stdout.write("[OK] hashcash stamp has passed " + \
                    "verification and is valid\n")
                sys.stdout.flush()
                sys.exit(0)
            else:
                sys.exit("[FAIL] hashcash stamp has failed " + \
                    "verification and is invalid")
        except AssertionError as exception:
            sys.stdout.write("[FAIL] ")
            sys.exit(exception)
    else:
        parser.error("failed to parse arguments")

    sys.exit(0)

def _parse_time_stamp(time_stamp):
    """
    This private method returns seconds since epoch
    for YYMMDD[hhmm[ss]] format time_stamp argument.
    """

    # Valid date formats are: YYMMDD, YYMMDDhhmm, YYMMDDhhmmss
    if len(time_stamp) == 12:
        epoch_time = time.mktime(time.strptime(time_stamp, '%y%m%d%H%M%S'))
    elif len(time_stamp) == 10:
        epoch_time = time.mktime(time.strptime(time_stamp, '%y%m%d%H%M'))
    elif len(time_stamp) == 6:
        epoch_time = time.mktime(time.strptime(time_stamp, '%y%m%d'))
    else:
        raise ValueError

    return epoch_time

def _build_args_parser():
    """
    This private method builds and returns 'ArgumentParser' object.
    """

    parser = argparse.ArgumentParser(description= \
        "A simple tool for minting and checking hashcash stamps", \
        add_help=True, epilog="EXIT STATUS: Exit code 0 success," + \
        " exit code 1 failure. EXAMPLE (mint): <%(prog)s -m -r " + \
        "email@example.com -b 20> EXAMPLE (check): <%(prog)s -c " + \
        "1:20:700101:email@example.com::yPbguc1Z9xto4Yc0:15ca " + \
        "-r email@example.com -b 20>")
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('-m', action="store_true", \
        help="Mint hashcash stamp for specified resource")
    action_group.add_argument('-c', action="store", \
        help="Check hashcash stamp specified as argument")
    parser.add_argument('-r', action="store", \
        help="Hashcash resource to mint or check for, e.g., an " + \
        "email or ip address")
    parser.add_argument('-b', type=int, action="store", \
        help="Number of leading zero bits required for minting " + \
        "or checking, default: 20")
    parser.add_argument('-e', action="store", \
        help="Hashcash stamp expiration when checking, notation: " + \
        "[s]econds, [m]inutes, [h]ours, [d]ays, default: 28days")
    parser.add_argument('-t', action="store", \
        help="Override current time when checking or use " + \
        "specified time as hashcash date field when minting, " + \
        "format: YYMMDD[hhmm[ss]]")
    parser.add_argument('-v', action="store_true", \
        help="Verbose output")

    return parser

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as interrupted:
        sys.exit(interrupted)