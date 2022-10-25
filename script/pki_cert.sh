#!/bin/bash

# Certificate Authority
pki --gen --type rsa --outform pem > ca-key.pem
pki --self --ca --lifetime 3652 --in ca-key.pem --dn "C=US, O=Lookout, CN=SSE Root CA" --outform pem > ca-cert.pem

# Server Certificate
pki --gen --type rsa --outform pem > server-key.pem
pki --req --type priv --in server-key.pem --dn "C=US, O=Lookout, CN=sse.lookout.com" --san sse.lookout.com --outform pem > serverReq.pem
pki --issue --cacert ca-cert.pem --cakey ca-key.pem --type pkcs10 --in serverReq.pem --lifetime 1826 --outform pem > server-cert.pem

# Client Certificate
pki --gen --type rsa --outform pem > client-key.pem
pki --req --type priv --in client-key.pem --dn "C=US, O=Lookout, CN=client.lookout.com" --san client.lookout.com --outform pem > clientReq.pem
pki --issue --cacert ca-cert.pem --cakey ca-key.pem --type pkcs10 --in clientReq.pem --lifetime 1826 --outform pem > client-cert.pem

mkdir -p certs/
rm -fr certs/*
cp ca-cert.pem certs/
cp ca-key.pem certs/
cp client-cert.pem certs/
cp client-key.pem certs/
cp server-cert.pem certs/
cp server-key.pem certs/
rm -f *.pem *.csr

