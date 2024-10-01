#!/bin/bash

set -e

echo "Give me your base64-encoded JS script (max decoded size $(ulimit -f)K)."
echo 'Input "EOF" on an empty line when done.'

while read -r -n 256; do
	if [ "$REPLY" = "EOF" ]; then
		break
	fi

	echo "$REPLY"
done | base64 -d > /tmp/script.js

flagdir="$(mktemp -d /tmp/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX)"
flagfile="$(mktemp $flagdir/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX)"

echo "$FLAG" > "$flagfile"
export FLAG="$flagfile"

set +e
./d8 --sandbox-testing /tmp/script.js &>/tmp/out
cat /tmp/out
