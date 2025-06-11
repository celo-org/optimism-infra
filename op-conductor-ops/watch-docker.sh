#!/bin/bash
set -e

Help()
{
   # Display Help
   echo "Syntax: watch -n <NETWORK>"
   echo "Options:"
   echo "n     Name of the network to watch. Supported values are alfajores-cel2, baklava-cel2 or mainnet-cel2."
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
	echo "-n (network) is compulsory. Supported values are alfajores-cel2, baklava-cel2 or mainnet-cel2"
	exit 1
fi

if [[ "${network}" != "alfajores-cel2" && "${network}" != "baklava-cel2" && "${network}" != "mainnet-cel2" ]]; then
    echo "Invalid network: ${network}. Supported values are alfajores-cel2, baklava-cel2 or mainnet-cel2"
    exit 1
fi

# Main loop
while true; do
    date
    ./op-conductor-ops -c ./$network.toml status $network
    sleep 10
done
