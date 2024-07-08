#!/bin/sh

echo "[+] Waiting for connections"
socaz --timeout 200 --flag-from-env FLAG --bind 1337 --cmd "sage chall.sage"
echo "[+] Exiting"