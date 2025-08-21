#! /bin/bash


if [ "$#" -lt 2 ]; then
    echo "Error: parameter is missing"
    exit 1
fi

writefile="$1"
writestr="$2"

## Validate create the folder if does not exist

#FILE_PATH="/path/to/your/new/file.txt"

# Extract the directory path
DIR_PATH=$(dirname "$writefile")

# Create the directory if it doesn't exist
mkdir -p "$DIR_PATH"

# Create the file if it doesn't exist
touch "$writefile"

# echo the string to that file
echo "$writestr" > "$writefile"