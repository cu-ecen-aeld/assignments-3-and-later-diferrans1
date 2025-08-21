#! /bin/bash

if [ "$#" -lt 2 ]; then
    echo "Error: parameter is missing"
    exit 1
fi

filedir="$1"
searchstr="$2"


if [[ ! -d "$filedir" ]]; then
  echo "${filesdir} does not represent a directory on the filesystem"
  exit 1
fi

MATCHING_FILES=$(grep -r "$searchstr" "$filedir" | wc -l)

echo "The number of files are $MATCHING_FILES and the number of matching lines are $MATCHING_FILES"
