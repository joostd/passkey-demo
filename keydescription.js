function parseASN1(data) {
    let offset = 0;

    function decode() {
        if (offset >= data.length) return null;

        // TAG
        const tag = data[offset++];
        // (ignoring class bits tag>>>6
        const constructed = (tag & 0x20) > 0
        let type = tag & 0x1f
        if (type == 0x1f) {	// multi-byte tag
          type = 0
          for (;;) {
            type = 128*type + (data[offset]&0x7f)
            if ((data[offset++]&0x80) == 0) break
          }
        }

        // LEN
        let length = data[offset++];
        // Handle Long-form length
        if (length & 0x80) {
            const numBytes = length & 0x7F;
            length = 0;
            for (let i = 0; i < numBytes; i++) {
                length = (length << 8) | data[offset++];
            }
        }

        // VAL
        const value = data.slice(offset, offset + length);
        const hexValue = Array.from(value).map(b => b.toString(16).padStart(2, '0')).join('');
        
        let node = {}
        if (constructed) {
            switch (type) {
              case 16:
                node.type = "SEQUENCE"
                break
              case 17:
                node.type = "SET"
                break
              default:
                node.tag = type
                break
            }
            const end = offset + length;
            node.value = [];
            const savedOffset = offset;
            while (offset < end) {
                node.value.push(decode());
            }
            offset = end;
        } else {
            switch (type) {
              case 1:
                node.type = "BOOLEAN"
                node.value = Boolean(hexValue)
                break
              case 2:
                node.type = "INTEGER"
                node.value = Number("0x"+hexValue)
                break
              case 4:
                node.type = "OCTET STRING"
                node.value = hexValue
                break
              case 5:
                node.type = "NULL"
                node.value = hexValue
                break
              case 10:
                node.type = "ENUMERATED"
                node.value = Number("0x"+hexValue)
                break
              default:
                node.todo = type
                node.value = hexValue
            }
            offset += length;
        }
        return node;
    }

    return decode();
}

// KeyDescription
// https://source.android.com/docs/security/features/keystore/attestation#attestation-v400

function integer(t) {
    console.assert(t.type == 'INTEGER', `INTEGER expected instead of ${t.type}`)
    return t.value
}

function octetstring(t) {
    console.assert(t.type == 'OCTET STRING', `OCTET STRING expected instead of ${t.type}`)
    return t.value
}

function setOfInteger(t) {
    console.assert(t.type == 'SET', `SET expected instead of ${t.type}`)
    console.assert(t.value.length == 1, `expecting singleton value for tag ${t.tag}`)
    let set = []
    for (item in t.value ) {
        set.push( integer(t.value[item]) )
    }
    return set
}

const enumVerifiedBootState = [ 'Verified', 'SelfSigned', 'Unverified', 'Failed' ]
const enumSecurityLevel = [ 'Software', 'TrustedEnvironment', 'StrongBox' ]

// https://cs.android.com/android/platform/superproject/+/android-latest-release:hardware/libhardware/include_all/hardware/keymaster_defs.h
const enumPurpose = [ 'encrypt', 'decrypt', 'sign', 'verify', 'derive_key', 'wrap', 'agree_key', 'attest_key' ]
const enumAlgorithm = { 1: 'RSA', 2: 'DSA', 3: 'EC', 32: 'AES', 33: '3DES', 128: 'HMAC', }
const enumDigest = [ 'NONE', 'MD5', 'SHA1', 'SHA_2_224', 'SHA_2_256', 'SHA_2_384', 'SHA_2_512', ]
const enumCurve = [ 'P_224', 'P_256', 'P_384', 'P_521', 'CURVE_25519', ]
const enumOrigin = [ 'generated', 'derived', 'imported', 'unknown', ]

// https://cs.android.com/android/platform/superproject/+/android-latest-release:hardware/libhardware/include_all/hardware/hw_auth_token.h
function authenticatorType(t) { // bitmap
  const type = []
  if( t&1) type.push("password")
  if( t&2) type.push("fingerprint")
  return type
}

function keyDescription(seq) {
    console.assert(seq.type == 'SEQUENCE', `SEQUENCE expected instead of ${seq.type}`)
    console.assert(seq.value[0].type == 'INTEGER')
    let attestationVersion = seq.value[0].value
    console.assert(seq.value[1].type == 'ENUMERATED', `ENUMERATED expected instead of ${seq.value[1].type}`)
    let attestationSecurityLevel = enumSecurityLevel[seq.value[1].value]
    console.assert(seq.value[2].type == 'INTEGER', `INTEGER expected instead of ${seq.value[2].type}`)
    let keymasterVersion = seq.value[2].value
    console.assert(seq.value[3].type == 'ENUMERATED', `ENUMERATED expected instead of ${seq.value[3].type}`)
    let keymasterSecurityLevel = enumSecurityLevel[seq.value[3].value]
    console.assert(seq.value[4].type == 'OCTET STRING', `OCTET STRING expected instead of ${seq.value[4].type}`)
    let attestationChallenge = seq.value[4].value
    console.assert(seq.value[5].type == 'OCTET STRING', `OCTET STRING expected instead of ${seq.value[5].type}`)
    let uniqueId = seq.value[5].value
    let softwareEnforced = authorizationList(seq.value[6])
    let hardwareEnforced = authorizationList(seq.value[7])
    return { attestationVersion, attestationSecurityLevel, keymasterVersion, keymasterSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, hardwareEnforced }
}

function rootOfTrust(seq) {
    console.assert(seq.type == 'SEQUENCE', `SEQUENCE expected instead of ${seq.type}`)
    console.assert(seq.value[0].type == 'OCTET STRING', `OCTET STRING expected instead of ${seq.value[0].type}`)
    let verifiedBootKey = seq.value[0].value
    console.assert(seq.value[1].type == 'BOOLEAN')
    let deviceLocked = seq.value[1].value
    console.assert(seq.value[2].type == 'ENUMERATED', `ENUMERATED expected instead of ${seq.value[2].type}`)
    let verifiedBootState = enumVerifiedBootState[seq.value[2].value]
    console.assert(seq.value[3].type == 'OCTET STRING', `OCTET STRING expected instead of ${seq.value[3].type}`)
    let verifiedBootHash = seq.value[3].value
    return { verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash }
}

function authorizationList(seq) {
    console.assert(seq.type == 'SEQUENCE', `SEQUENCE expected instead of ${seq.type}`)
    let list = {}
    for (v in seq.value) {
        const t = seq.value[v]
        console.assert(t.value.length == 1, `expecting singleton value for tag ${t.tag}`)
        switch (t.tag) {
            case 1:
                list['purpose'] = enumPurpose[setOfInteger(t.value[0])]
                break
            case 2:
                list['algorithm'] = enumAlgorithm[integer(t.value[0])]
                break
            case 3:
                list['keySize'] = integer(t.value[0])
                break
            case 4:
                list['blockMode'] = integer(t.value[0])
                break
            case 5:
                list['digest'] = setOfInteger(t.value[0]).map((n) => enumDigest[n]);
                break
            case 6:
                list['padding'] = setOfInteger(t.value[0])
                break
            case 7:
                list['callerNonce'] = nul(t.value[0])
                break
            case 8:
                list['minMacLength'] = integer(t.value[0])
                break
            case 10:
                list['ecCurve'] = enumCurve[integer(t.value[0])]
                break
            case 200:
		list['rsaPublicExponent'] = integer(t.value[0])
                break
            case 203:
		list['mgfDigest'] = setOfInteger(t.value[0])
                break
            case 303:
                list['rollbackResistance'] = nul(t.value[0])
                break
            case 305:
                list['earlyBootOnly'] = nul(t.value[0])
		break
            case 400:
		list['activeDateTime'] = new Date(integer(t.value[0])).toString();
                break
            case 401:
		list['originationExpireDateTime'] = new Date(integer(t.value[0])).toString();
                break
            case 402:
		list['usageExpireDateTime'] = new Date(integer(t.value[0])).toString();
                break
            case 405:
		list['usageCountLimit'] = integer(t.value[0])
                break
            case 502:
                break
		list['userSecureId'] = integer(t.value[0])
            case 503:
 		list['noAuthRequired'] = nul(t.value[0])
                break
            case 504:
		list['userAuthType'] = authenticatorType(integer(t.value[0]))
                break
            case 505:
		list['authTimeout'] = integer(t.value[0])
                break
            case 506:
		list['allowWhileOnBody'] = nul(t.value[0])
                break
	    case 507:
		list['trustedUserPresenceReq'] = nul(t.value[0])
		break
	    case 508:
		list['trustedConfirmationReq'] = nul(t.value[0])
		break
	    case 509:
		list['unlockedDeviceReq'] = nul(t.value[0])
		break
            case 600:
		list['allApplications'] = nul(t.value[0])
                break
            case 701:
		list['creationDateTime'] = new Date(integer(t.value[0])).toString();
                break
            case 702:
		list['origin'] = enumOrigin[integer(t.value[0])]
                break
            case 703:
		list['rollbackResistant'] = nul(t.value[0])
                break
            case 704:
		list['rootOfTrust'] = rootOfTrust(t.value[0])
                break
            case 705:
		list['osVersion'] = integer(t.value[0])
                break
            case 706:
		list['osPatchLevel'] = integer(t.value[0])
                break
            case 709:
		list['attestationApplicationId'] = octetstring(t.value[0])
                break
            case 710:
		list['attestationIdBrand'] = octetstring(t.value[0])
                break
            case 711:
		list['attestationIdDevice'] = octetstring(t.value[0])
                break
            case 712:
		list['attestationIdProduct'] = octetstring(t.value[0])
                break
            case 713:
		list['attestationIdSerial'] = octetstring(t.value[0])
                break
            case 714:
		list['attestationIdImei'] = octetstring(t.value[0])
                break
            case 715:
		list['attestationIdMeid'] = octetstring(t.value[0])
                break
            case 716:
		list['attestationIdManufacturer'] = octetstring(t.value[0])
                break
            case 717:
		list['attestationIdModel'] = octetstring(t.value[0])
                break
            case 718:
		list['vendorPatchLevel'] = integer(t.value[0])
                break
            case 719:
		list['bootPatchLevel'] = integer(t.value[0])
                break
            case 720:
		list ['deviceUniqueAttestation'] = nul(t.value[0])
                break
            case 723:
		list['attestationIdSecondImei'] = octetstring(t.value[0])
                break
            case 724:
		list['moduleHash'] = octetstring(t.value[0])
                break
            default:
                list['tag'+t.tag] = t.value
        }
    }
    return list
}

const hexInput = "3082017e020201900a0101020201900a01010420f743761d0ac737388077e0f8d3a48150a3585f4d2e5cfe17ac2f23b2cb187bb0040030819dbf853d080206019b98061b2abf85456704653063313d301b0416636f6d2e676f6f676c652e616e64726f69642e677366020124301e0416636f6d2e676f6f676c652e616e64726f69642e676d7302040f31f44331220420f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83bf85542204203b2bfb758e1087d2fb8cf348aa21cf152f62adcc0689b822c7f2ae5780cf6c873081a9a1053103020102a203020103a30402020100a5053103020104aa03020101bf837803020103bf83790302010abf853e03020100bf85404c304a04209ac4174153d45e4545b0f49e22fe63273999b6ac1cb6949c3a9f03ec8807eee90101ff0a01000420d69902e18d96caf8d690638cfc5f9a7991d5e45c96dadb54c25e21dd74f39c0fbf8541050203027100bf8542050203031710bf854e06020401350245bf854f06020401350245";

const input = Uint8Array.from(hexInput.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
a = parseASN1(input)
//console.log(a);
kd = keyDescription(a)
console.log(kd);

