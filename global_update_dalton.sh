#!/bin/bash

source ~/.virtualenv/dalton/bin/activate

flags=--dry-run

REGIONS=( us-east-1 us-west-1 us-west-2 eu-west-1 ap-northeast-1 )
for region in "${REGIONS[@]}"
do
  python dalton.py ${flags} prod ${region}
done