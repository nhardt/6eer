# 6eer

## About

Test code to send an encrpyted message over ipv6. Keys are hardcoded, server
listens on all ipv6 address, client will take an optional address, default is
"::1".

## Usage

### C

#### Prerequisites

sudo apt install libsodium-dev

#### Build

cd c
rm client server; gcc client.c -o client -lsodium && gcc server.c -o server -lsodium

#### Run

./server
./client

## Reference

### Networking

IPV6 code is from here:
https://gist.github.com/jirihnidek/388271b57003c043d322

### Crypto

https://doc.libsodium.org/public-key_cryptography/sealed_boxes

