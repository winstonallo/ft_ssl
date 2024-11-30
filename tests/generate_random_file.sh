#!/bin/bash

FILE_SIZE=100

echo "Generating a $FILE_SIZE MB file with random data: $FILE_NAME"
dd if=/dev/urandom of="$FILE_NAME" bs=1M count="$FILE_SIZE" status=progress

if [[ $? -eq 0 ]]; then
    echo "File generated successfully: $FILE_NAME"
else
    echo "Failed to generate the file."
    exit 1
fi