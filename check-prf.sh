#!/bin/bash

HID="$(fido2-token -L | head -1 | cut -d: -f1-2)"

RPID=passkey.joostd.nl

if [[ ! -f cred ]]
then
	# challenge:
	cat /dev/urandom | head -c32 | base64 > cred.in
	echo $RPID >> cred.in
	echo user name >> cred.in
	# userID:
	cat /dev/urandom | head -c16 | base64 >> cred.in
	echo "# creating new credential..."
	fido2-cred -M -h -i cred.in $HID | fido2-cred -V -h -o cred
	rm cred.in
	echo created new cred
fi
echo Credential ID:
head -1 cred | base64 -d | xxd -p -c0

[[ -f salt ]] || cat /dev/urandom | head -c32 > ./salt
echo salt:
cat ./salt | xxd -p -c0

# challenge:
cat /dev/urandom | head -c32 | base64 > assert.in
echo $RPID >> assert.in
# credential ID:
head -1 cred >> assert.in
(echo -en "WebAuthn PRF\0"; cat salt)| openssl sha256 -binary | base64 >> assert.in
#cat salt | base64 >> assert.in

echo "# get assertion"
fido2-assert -G -h -t pin=true -i assert.in $HID | tee assert.out | fido2-assert -V -h <(tail -n +2 cred) es256
echo "# PRF output with UV:"
tail -1 assert.out | base64 -d | xxd -p -c0
#echo "# PRF output without UV:"
#fido2-assert -G -h -i assert.in $HID | tee assert.out | fido2-assert -V -h <(tail -n +2 cred) es256
#tail -1 assert.out | base64 -d | xxd -p -c0
rm assert.in

echo
#echo open "'http://localhost:8080/check-prf.html?credid=$(head -1 cred | base64 -d | xxd -p -c0)&salt=$(xxd -p -c0 ./salt)&prf=$(tail -1 assert.out | base64 -d | xxd -p -c0)'"
echo open "'https://$RPID/check-prf.html?credid=$(head -1 cred | base64 -d | xxd -p -c0)&salt=$(xxd -p -c0 ./salt)&prf=$(tail -1 assert.out | base64 -d | xxd -p -c0)'"
rm assert.out
