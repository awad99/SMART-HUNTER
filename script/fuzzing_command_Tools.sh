#!/bin/bash

sudo openvpn --config GrowingFlaberella83-asia-pasific-1---singapore-hackviser.ovpn --auth-user-pass auth.txt --daemon
sleep 10

# Fuzzing
URL=$(cat fuzzing_Target.txt)
Wordlist=$(cat WordList_Use.txt)
result_file="ffuf_results.json"

echo "Starting fuzzing..."
echo "Starting fuzzing for subdomains..."
ffuf -w "$Wordlist" -u "https://FUZZ/$URL" \
     -mc 200 \
     -t 50 \
     -o "$result_file" \
     -of json

# Cleanup
echo "Cleaning up..."
sudo pkill openvpn