#!/bin/bash

# Maximum number of attempts
max_attempts=30

# Counter for the current attempt
attempt=1

while [ $attempt -le $max_attempts ]; do
    echo "Attempt $attempt of $max_attempts..."
    
    ansible-playbook -i inventory sync.yml
    
    # Check the exit status of the command
    if [ $? -eq 0 ]; then
        echo "Command succeeded."
        break
    else
        echo "Command failed."
        # Wait for 30 seconds if the command fails
        if [ $attempt -lt $max_attempts ]; then
            echo "Waiting for 30 seconds before retrying..."
            sleep 30
        fi
    fi
    
    # Increment the attempt counter
    ((attempt++))
done

if [ $attempt -gt $max_attempts ]; then
    echo "Reached maximum attempts. Exiting."
fi
