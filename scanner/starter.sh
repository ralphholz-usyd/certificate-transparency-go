#!/bin/bash

declare -a arr=()

while IFS=, read -r col1 col2
do
    arr+=($col2)
done < logs.latest.csv

#echo $arr
for i in "${arr[@]}"
do
    echo "Found a log with URL ""$i";
    ./scanlog -log_uri "$i" --num_workers 100;
    wait;
    sleep 2;
done