#!/bin/bash
echo "usage: ./$0 ID_file DATA_file groundtruth_output_file"
echo "e.g. : ./get_ground_truth.sh A_PIR_ID.csv B_PIR_DATA.csv C_PIR_RESULTS.csv"
echo "remember use 'dos2unix' to convert input files before getting ground truth"
for line in $(cat $1 $(echo)); do
	echo $line
	cat $2 | grep $line >>$3
done
