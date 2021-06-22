#!/bin/bash

# Author: John Carter
# Created: 2021/04/17 21:20:18
# Last modified: 2021/06/12 15:19:39

# Script to start the data collection 
# process for malware detection
# NOTE: Must be run as root

RED=$'\e[1;31m'
GRN=$'\e[1;32m'
END=$'\e[0m'

help() {
   echo "[${RED}ERROR${END}] USAGE: $0 <syscall log file> <cicflowmeter csv file>" 
   exit 1
}

exit_process() {
    echo "[${GRN}INFO${END}] Killing Heimdall..."
    syscall-sensor stop
    echo "[${GRN}INFO${END}] Killing CICFlowMeter..."
    pkill cicflowmeter
    echo "[${RED}EXIT${END}] Script terminated"
    exit 1
}

trap exit_process INT TERM

if (( EUID != 0 )); then
   echo "[${RED}ERROR${END}] This script must be run as root" 
   exit 1
fi

if [[ $# -ne 2 ]]; then
    help
fi

echo "[${GRN}INFO${END}] Heimdall saving system call data to $1"
syscall-sensor start -s -t -p -n -o $1

echo "[${GRN}INFO${END}] CICFlowMeter saving network traffic data to $2"
cicflowmeter -i ap0 -c $2
