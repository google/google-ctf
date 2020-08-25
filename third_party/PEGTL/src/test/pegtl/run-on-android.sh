#!/bin/bash

tmp_dir="/data/local/tmp"

exename=$1

adb push $exename $tmp_dir
adb shell $tmp_dir/$exename
adb shell rm $tmp_dir/$exename