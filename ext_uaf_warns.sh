#!/bin/bash
#To collect and classify the warnings from the raw log file.
#$1: path/to/log

#Create a dedicated directory to hold the warnings.
log_pref=${1%/*}
log=${1##*/}
dir=${log_pref}/warns-${log%.*}-$(date +%F)
echo "Make dir: "$dir
mkdir $dir

echo "Extract the warnings: UAFDetector."
python ext_uaf_warns.py $1 UAFDetector > $dir/uaf

if [ ! -s $dir/uaf ]; then
    #No warnings generated, delete the output folder.
    rm -r $dir
    echo "No warnings, output folder deleted."
fi

#Test whether the log file is complete.
res=`tail -50 $1 | grep "All done"`
if [ -z "$res" ]; then
    echo $1" is not complete."
else
    echo $1" is complete."
fi