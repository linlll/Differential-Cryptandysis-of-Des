#!/bin/bash

rm -rf out
if [ ! -d "./out" ]
then
  mkdir out
fi

ALL=100

for j in $(seq 1 ${ALL})
do
  python 7des_diff_1.py >> ./out/7des_diff_1.txt
done

GOOD=$(cat ./out/7des_diff_1_out.txt | grep successfully | wc -l)

echo "" >> ./out/results.txt
echo "========================================================================" >> ./out/results.txt
echo "Differential Cryptandysis of "7"-round DES. The accuracy is "${GOOD}"/"${ALL} >> ./out/results.txt
echo "========================================================================" >> ./out/results.txt
