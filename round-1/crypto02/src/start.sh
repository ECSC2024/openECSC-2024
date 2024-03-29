#!/bin/sh

echo "[+] Waiting for connections"
socaz --timeout 90 --flag-from-env FLAG --bind 1337 --cmd "sage another_matrix_ke.sage"
echo "[+] Exiting"