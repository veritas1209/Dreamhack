#!/bin/bash
cd /host/realdump
: > /host/secrets.txt
for i in $(seq 0 994); do
  out=$(/host/extract ./bin_$i bin_$i 2>/dev/null)
  echo "$i $out" >> /host/secrets.txt
  (( i % 100 == 0 )) && echo "[$i] $out"
done
echo "DONE"; echo -n "ec!=0 개수: "; awk '$3!=0' /host/secrets.txt|wc -l
