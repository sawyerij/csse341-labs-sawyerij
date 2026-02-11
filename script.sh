#!/bin/bash

for FILE in *+_temp; do
    echo "Processing file: $FILE"
		mv -- "$FILE" "${FILE%+_temp}"
done
