#!/bin/bash

LOG_FILE=${LOG_FILE:-/dev/null}

get_token() {
    local token
    token=$(head -c 8 /dev/urandom|xxd -p)
    mkdir -p $token
	echo DBG: created bucket with token: $token > $LOG_FILE
    echo $token
}

write_file() {
	local token
	local filename
	local data
    echo -n Enter token: 
    read token
	echo -n Enter file name: 
	read filename

	if [[ ! $token =~ ^[0-9a-f]{16}$ ]] || [[ ! $filename =~ ^[a-zA-Z0-9]+$ ]] || [[ ! -d $token ]]; then
		echo ERR: failed to write to bucket with credentials: $token/$filename > $LOG_FILE
		echo Invalid credentials
		return
	fi

	echo DBG: accessing bucket in write mode $token/$filename > $LOG_FILE
	echo Enter the data in base64:
	read data

    if [[ ! $data =~ ^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$ ]]; then
		echo ERR: user provided invalid base64 string > $LOG_FILE
		echo Invalid base64 string
		return
	fi
	
	echo $data | base64 -d > $token/$filename
	echo Done
}


read_file() {
	local token
	local filename
    echo -n Enter token: 
    read token
	echo -n Enter file name: 
	read filename

	if [[ ! $token =~ ^[0-9a-f]{16}$ ]] || [[ ! $filename =~ ^[a-zA-Z0-9]+$ ]] || [[ ! -d $token ]] || [[ ! -f $token/$filename ]]; then
		echo ERR: failed to read from bucket with credentials: $token/$filename > $LOG_FILE
		echo Invalid credentials
		return
	fi

	echo DBG: accessing bucket in read mode $token/$filename > $LOG_FILE
	cat $token/$filename | base64
	echo Done
}

# Store flag in secret bucket
flag_token=$(get_token)
echo $FLAG > $flag_token/flag

# Main menu
while true; do
    echo Choose an option:
    echo 1. Get bucket token
    echo 2. Write file in bucket
    echo 3. Read file from bucket
    echo 4. Exit
    read option

    case $option in
        1)
            token=$(get_token)
            echo Your secret token is: $token
            ;;
        2)
            write_file
            ;;
        3)
            read_file
            ;;
        4)
            echo Exiting...
            break
            ;;
        *)
            echo Invalid option. Please try again.
            ;;
    esac
done
