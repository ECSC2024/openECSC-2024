#!/usr/bin/env bash

readelf -a $1 | grep flag_ | cut -d '_' -f3 | cut -d ' ' -f1 | awk '{print}' ORS=""
