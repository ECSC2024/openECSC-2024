#!/usr/bin/env python3

import logging
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urlunparse

import requests

logging.disable()

CHECKER_NAME = os.environ.get("CHECKER_NAME", "checker")
CHECKER_SECRET = os.environ["CHECKER_SECRET"]

URL = os.environ.get("URL", "https://mammamia.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]


def make_admin_url():
    url = urlparse(URL)
    return urlunparse((url.scheme, 'admin1.' + url.netloc, url.path, url.params, url.query, url.fragment))


ADMIN_URL = make_admin_url()


def auth():
    r = requests.post(f"{ADMIN_URL}/auth/login", json={"name": CHECKER_NAME, "secret": CHECKER_SECRET})
    r.raise_for_status()
    return r.json()["token"]


def get_labs(token):
    r = requests.get(f"{ADMIN_URL}/labs?page=1&pageSize=20&sortOrder=DESC&orderBy=createdAt&status=running",
                     headers={"Authorization": f"Bearer {token}"})
    r.raise_for_status()
    return r.json()


def get_datetime(s):
    # Python 3.10 does not support T and Z in fromisoformat
    return datetime.fromisoformat(s.replace("Z", "+00:00").replace("T", " "))


def main():
    # Check team URL is reachable
    r = requests.get(URL, timeout=5)
    if r.status_code != 200:
        raise Exception(f"Unexpected status code: {r.status_code}")

    # Lab health check
    token = auth()
    labs = get_labs(token)["values"]

    # Labs with isHealthy = false
    unhealthy_lab_ids = []

    # Labs with isHealthy = null | None
    broken_lab_ids = []

    for lab in labs:
        # A lab is broken if it has not performed a health check within the last 7 minutes (runs every 5 minutes + 1 minute cron to digest the results + 1 minute buffer)
        # A lab is unhealthy if the health check failed and is >2 minutes older than the lab start time (false positives are possible in rare cases, so better to be safe than sorry)

        startedAt = get_datetime(lab["startedAt"])

        # Check if broken
        if lab["healthCheckedAt"] is None or lab["isHealthy"] is None:
            if startedAt < (datetime.now(tz=timezone.utc) - timedelta(minutes=7)):
                broken_lab_ids.append(lab["id"])
            continue

        # Check if unhealthy
        if lab["isHealthy"] is False:
            if get_datetime(lab["healthCheckedAt"]) > (startedAt + timedelta(minutes=2)):
                unhealthy_lab_ids.append(lab["id"])

    if len(unhealthy_lab_ids) == 0 and len(broken_lab_ids) == 0:
        flag = "openECSC{even_the_hound_of_hades_could_not_safeguard_the_secret_recipe_abcd1234}"
        print(flag)
        exit(0)

    print(f"Unhealthy labs: {unhealthy_lab_ids}")
    print(f"Broken labs: {broken_lab_ids}")
    exit(1)


if __name__ == '__main__':
    main()
