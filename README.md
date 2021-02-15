# 6eer

## About

Test code to send an encrpyted message over ipv6. Keys are hardcoded, server
listens on all ipv6 address, client will take an optional address, default
connection is to "::1". Server by default listens on all ipv6 addresses.

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

### JS/TS

#### Prerequisites

Developed on nodejs 15.6.0

`npm install`

#### Build

`npm run build`

#### Run

`npm run client`
`npm run server`

Both commands can take a a parameter to listen on or connect to.

## Reference

### Networking

IPV6 c code is from here:
https://gist.github.com/jirihnidek/388271b57003c043d322

Node.js client/server code started from here:
https://gist.github.com/sid24rane/2b10b8f4b2f814bd0851d861d3515a10
https://nodejs.org/dist/latest-v15.x/docs/api/net.html

### Crypto

https://doc.libsodium.org/public-key_cryptography/sealed_boxes
https://github.com/dchest/tweetnacl-js/wiki/Examples

