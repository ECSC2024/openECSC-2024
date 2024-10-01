#!/usr/bin/env python3
from subprocess import check_output, CalledProcessError
from string import ascii_lowercase, ascii_uppercase, digits
from os import environ


ALPHABET = ascii_lowercase + ascii_uppercase + digits + "{}_"


def main():
    try:
        user_input = input("What's your wisdom, Neo? ")
        for c in user_input:
            if c not in ALPHABET:
                print("Bad char m8")
                return
        check_output(["/home/user/matrix", user_input])
        print("Congrats! Here is your flag", environ.get("FLAG", "This means that admins forgot to set the flag in environ. Write them, seriously"))
    except CalledProcessError:
        print("Process did not exit successfully")
    except Exception as exc:
        print(exc)
        print("Something else broken")


if __name__ == '__main__':
    main()
