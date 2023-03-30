import * as cborx from "cbor-x";
import { COSEPublicKeyEC2, COSEPublicKey, COSEKEYS } from "./cose";
import { AsnParser } from '@peculiar/asn1-schema';
import { ECDSASigValue } from '@peculiar/asn1-ecc';

/*
  signal input pubkey[2][k]; 
  signal input r[k];
  signal input s[k];

  signal input challenge[max_challenge]; // options.challenge

  signal input client_data_json[max_client_json]; 
  signal input challenge_offset; // where the challenge is in the json, C.challenge
  signal input authenticator_data[max_auth_data]; // 37 bytes or more, just do an array of 37*8 bits, decoded
*/

// export async function getCircuitInputs(
//     pubkey,
//     r, 
//     s,
//     challenge, 
//     client_data_json, 
//     authenticator_data
//   ) {
//     console.log("Starting processing of inputs");
//     // Derive modulus from signature
//     // const modulusBigInt = bytesToBigInt(pubKeyParts[2]);
//     const modulusBigInt = rsa_modulus;
//     // Message is the email header with the body hash
//     const prehash_message_string = msg;
//     // const baseMessageBigInt = AAYUSH_PREHASH_MESSAGE_INT; // bytesToBigInt(stringToBytes(message)) ||
//     // const postShaBigint = AAYUSH_POSTHASH_MESSAGE_PADDED_INT;
//     const signatureBigInt = rsa_signature;

//     // Perform conversions
//     const prehashBytesUnpadded =
//       typeof prehash_message_string == "string"
//         ? new TextEncoder().encode(prehash_message_string)
//         : Uint8Array.from(prehash_message_string);
//     const postShaBigintUnpadded =
//       bytesToBigInt(
//         stringToBytes((await shaHash(prehashBytesUnpadded)).toString())
//       ) % CIRCOM_FIELD_MODULUS;

//     // Sha add padding
//     const [messagePadded, messagePaddedLen] = await sha256Pad(
//       prehashBytesUnpadded,
//       MAX_HEADER_PADDED_BYTES
//     );

//     // Ensure SHA manual unpadded is running the correct function
//     const shaOut = await partialSha(messagePadded, messagePaddedLen);
//     assert(
//       (await Uint8ArrayToString(shaOut)) ===
//         (await Uint8ArrayToString(
//           Uint8Array.from(await shaHash(prehashBytesUnpadded))
//         )),
//       "SHA256 calculation did not match!"
//     );

//     // Compute identity revealer
//     let circuitInputs;
//     const modulus = toCircomBigIntBytes(modulusBigInt);
//     const signature = toCircomBigIntBytes(signatureBigInt);

//     const message_padded_bytes = messagePaddedLen.toString();
//     const message = await Uint8ArrayToCharArray(messagePadded); // Packed into 1 byte signals
//     const base_message = toCircomBigIntBytes(postShaBigintUnpadded);

//     const address = bytesToBigInt(fromHex(eth_address)).toString();
//     const address_plus_one = (
//       bytesToBigInt(fromHex(eth_address)) + 1n
//     ).toString();

//     if (circuit === CircuitType.RSA) {
//       circuitInputs = {
//         modulus,
//         signature,
//         base_message,
//       };
//     } else if (circuit === CircuitType.JWT) {
//       circuitInputs = {
//         message,
//         modulus,
//         signature,
//         message_padded_bytes,
//         address,
//         address_plus_one,
//       };
//     } else {
//       assert(circuit === CircuitType.SHA, "Invalid circuit type");
//       circuitInputs = {
//         m,
//         m_padded_bytes,
//       };
//     }
//     return {
//       circuitInputs,
//       valid: {},
//     };
//   }

type PublicKey = {
  x: Uint8Array, 
  y: Uint8Array
}

type UnwrappedEC2Sig = {
  r: Uint8Array, 
  s: Uint8Array
}

const encoder = new cborx.Encoder({
  mapsAsObjects: false,
  tagUint8Array: false,
});

/**  Pass in Uint8Array public key! Returns a COSEPublicKey **/
function decodeCredentialPublicKey(publicKey: Uint8Array) : COSEPublicKeyEC2 {
  return decodeFirst<COSEPublicKeyEC2>(publicKey);
}

/**  Pass in Uint8Array public key! Returns a COSEPublicKey **/
function decodeFirst<Type>(input : Uint8Array) : Type{
  const decoded = encoder.decodeMultiple(input) as undefined | Type[];

  if (decoded === undefined) {
    throw new Error('CBOR input data was empty');
  }

  const [first] = decoded;

  console.log("printing CBOR decoded object");
  console.log(first);
  return first;
}

function extractXY(cosePublicKey: COSEPublicKeyEC2) : PublicKey {

  const x = cosePublicKey.get(COSEKEYS.x);
  const y = cosePublicKey.get(COSEKEYS.y);

  return {
    x, 
    y
  } as PublicKey;
}

/**
 * Determine if the DER-specific `00` byte at the start of an ECDSA signature byte sequence
 * should be removed based on the following logic:
 *
 * "If the leading byte is 0x0, and the the high order bit on the second byte is not set to 0,
 * then remove the leading 0x0 byte"
 */
function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

function unwrapEC2Signature(signature: Uint8Array): UnwrappedEC2Sig {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }

  // const finalSignature = isoUint8Array.concat([rBytes, sBytes]);

  return {
    r: rBytes, 
    s: sBytes
  };
}

function byteString(n : number) {
  if (n < 0 || n > 255 || n % 1 !== 0) {
      throw new Error(n + " does not fit in a byte");
  }
  return ("000000000" + n.toString(2)).substr(-8)
}

export async function generate_inputs() {
  /* PUBKEY */
  const pubkeyArray = Uint8Array.from([
    165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 223, 52, 212, 122, 119, 163, 255, 140,
    25, 160, 160, 203, 191, 255, 245, 163, 118, 172, 71, 165, 230, 33, 238, 253,
    181, 115, 241, 212, 248, 123, 44, 246, 34, 88, 32, 48, 54, 44, 241, 60, 245,
    49, 50, 8, 26, 253, 153, 246, 169, 148, 200, 222, 28, 34, 154, 155, 64, 47,
    87, 15, 141, 178, 143, 128, 115, 101, 182,
  ]);

  const decodedPubkey = decodeCredentialPublicKey(pubkeyArray);
  const pubkey = extractXY(decodedPubkey)

  console.log("extracted x y")
  console.log(pubkey)
  
  /* SIGNATURE */
  const signature =
    "MEQCIE3GC4J3W4iKrKk1BmjDMOB8awXNBcBg1yWNzlGVPzi2AiAiIoN_rZf1o8BXP4OsR6PTsZx6poe77ymy7ddRw8Xyig";
  let sig_buffer = Buffer.from(signature, "base64");
  let sig = unwrapEC2Signature(sig_buffer);

  console.log("unwrapped sig")
  console.log(sig)

  // TODO: split signature

  /* CHALLENGE */
  // not base64 encoded
  const challenge = "VQjA4To46s1VqFP3N5eOqGElbL8f6K6s9ExV3h-UTe8";

  /* CLIENT DATA JSON */
  // TODO: might need base64url conversion stuff
  const client_data_json =
    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiR0cyRGdLNkFPelJJOUJZdGNVUGdkaTFZRFVlVlVVQnEtVW1GeFpCbU9YSSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9";
  let client_data = Buffer.from(client_data_json, "base64");

  console.log("decoded client data");
  console.log(client_data);

  // TODO: get challenge offset

  /* AUTHENTICATOR DATA */
  const auth_data = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA"
  let auth_data_decoded = Buffer.from(auth_data, "base64url");

  console.log("decoded auth data")
  console.log(auth_data_decoded)
  
  let auth_data_bin = [] as string[]
  for (var i = 0; i < auth_data_decoded.length; i ++) {
    let bin_byte = byteString(auth_data_decoded[i]).split("")

    auth_data_bin = auth_data_bin.concat(bin_byte)

  }

  console.log("binary auth data")
  console.log(auth_data_bin)
}

async function do_generate() {
  const gen_inputs = await generate_inputs();
  return gen_inputs;
}

// If main
if (typeof require !== "undefined" && require.main === module) {
  // debug_file();
  const circuitInputs = do_generate().then((res) => {
    // console.log("Writing to file...");
    // console.log(res)
    // fs.writeFileSync(`./jwt.json`, JSON.stringify(res), { flag: "w" });
  }
  );
  // gen_test();
}