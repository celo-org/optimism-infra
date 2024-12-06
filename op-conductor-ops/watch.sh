#!/bin/bash
set -e

Help()
{
   # Display Help
   echo "Syntax: watch -n <NETWORK>"
   echo "Options:"
   echo "n     Name of the network to watch. Supported values are alfajores or baklava."
   echo "h     Print this Help."
   echo
}

while getopts n:h flag
do
    case "${flag}" in
    	h) # display Help
           Help
           exit;;
        n) network=${OPTARG};;
    esac
done

if [ -z ${network+x} ]; then
	echo "-n (network) is compulsory. Supported values are alfajores or baklava."
	exit 1
fi

if [[ "${network}" != "alfajores" && "${network}" != "baklava" ]]; then
    echo "Invalid network: ${network}. Supported values are alfajores or baklava."
    exit 1
fi

# Start kubectl proxy in the background
kubectl proxy &
PID=$!

# Define a cleanup function to kill the background process
cleanup() {
    echo "Caught interrupt signal. Cleaning up kubectl proxy process."
    kill $PID
    exit 0
}

# Trap the interrupt signal (SIGINT) and call the cleanup function
trap cleanup SIGINT

# Main loop
while true; do
    date
    ./op-conductor-ops -c ./$network.toml status $network-cel2
    sleep 10
done
