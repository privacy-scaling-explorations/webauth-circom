import * as cborx from "cbor-x";
import { COSEPublicKeyEC2, COSEPublicKey, COSEKEYS } from "./cose";
import { AsnParser } from '@peculiar/asn1-schema';
import { ECDSASigValue } from '@peculiar/asn1-ecc';

import * as fs from "fs";

/*
  signal input pubkey[2][k]; 
  signal input r[k];
  signal input s[k];

  signal input challenge[max_challenge]; // options.challenge

  signal input client_data_json[max_client_json]; 
  signal input challenge_offset; // where the challenge is in the json, C.challenge
  signal input authenticator_data[max_auth_data]; // 37 bytes or more, just do an array of 37*8 bits, decoded
*/

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

// Works only on 32 bit sha text lengths
function int32toBytes(num: number): Uint8Array {
  let arr = new ArrayBuffer(4); // an Int32 takes 4 bytes
  let view = new DataView(arr);
  view.setUint32(0, num, false); // byteOffset = 0; litteEndian = false
  return new Uint8Array(arr);
}

function int8toBytes(num: number): Uint8Array {
  let arr = new ArrayBuffer(1); // an Int8 takes 4 bytes
  let view = new DataView(arr);
  view.setUint8(0, num); // byteOffset = 0; litteEndian = false
  return new Uint8Array(arr);
}

function mergeUInt8Arrays(a1: Uint8Array, a2: Uint8Array): Uint8Array {
  // sum of individual array lengths
  var mergedArray = new Uint8Array(a1.length + a2.length);
  mergedArray.set(a1);
  mergedArray.set(a2, a1.length);
  return mergedArray;
}

function assert(cond: boolean, errorMessage: string) {
  if (!cond) {
    throw new Error(errorMessage);
  }
}

// Puts an end selector, a bunch of 0s, then the length, then fill the rest with 0s.
async function sha256Pad(
  prehash_prepad_m: Uint8Array,
  maxShaBytes: number
): Promise<[Uint8Array, number]> {
  let length_bits = prehash_prepad_m.length * 8; // bytes to bits
  let length_in_bytes = int32toBytes(length_bits);
  prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int8toBytes(2 ** 7));
  while (
    (prehash_prepad_m.length * 8 + length_in_bytes.length * 8) % 512 !==
    0
  ) {
    prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int8toBytes(0));
  }
  prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, length_in_bytes);
  assert(
    (prehash_prepad_m.length * 8) % 512 === 0,
    "Padding did not complete properly!"
  );
  let messageLen = prehash_prepad_m.length;
  while (prehash_prepad_m.length < maxShaBytes) {
    prehash_prepad_m = mergeUInt8Arrays(prehash_prepad_m, int32toBytes(0));
  }
  assert(
    prehash_prepad_m.length === maxShaBytes,
    "Padding to max length did not complete properly!"
  );

  return [prehash_prepad_m, messageLen];
}

async function Uint8ArrayToCharArray(a: Uint8Array): Promise<string[]> {
  return Array.from(a).map((x) => x.toString());
}

const MAX_CHALLENGE = 100
const MAX_CLIENT_JSON = 512
const MAX_AUTH_DATA = 512

async function getCircuitInputs(
  sig: UnwrappedEC2Sig,
  publicKey: PublicKey,
  challengeInput: string,
  challengeOffset: Number,
  clientDataJson: Uint8Array,
  authenticatorData: string[]
  ) {
    console.log("Starting processing of inputs");
    console.log(authenticatorData.toString())
    const hi = new TextEncoder().encode(authenticatorData.toString())
    console.log("hi")
    console.log(hi.length)

    // PAD client_data_json
    const [clientDataPadded, clientDataPaddedLen] = await sha256Pad(
      clientDataJson,
      MAX_CLIENT_JSON
    );

    // PAD challenge 
    const [challengePadded, challengePaddedLen] = await sha256Pad(
      new TextEncoder().encode(challengeInput),
      MAX_CHALLENGE
    );

    // PAD authenticator_data
    const [authDataPadded, authDataPaddedLen] = await sha256Pad(
      new TextEncoder().encode(authenticatorData.join("")), 
      MAX_AUTH_DATA
    )

    // Compute identity revealer
    let circuitInputs;

    const challenge = await Uint8ArrayToCharArray(challengePadded); 
    const authenticator_data = await Uint8ArrayToCharArray(authDataPadded); 
    const client_data_json = await Uint8ArrayToCharArray(clientDataPadded); 
    
    const r = await Uint8ArrayToCharArray(sig.r);
    const s = await Uint8ArrayToCharArray(sig.s);

    const xCircom = await Uint8ArrayToCharArray(publicKey.x);
    const yCircom = await Uint8ArrayToCharArray(publicKey.y);

    const pubkey = new Array(2)
    pubkey[0] = xCircom
    pubkey[1] = yCircom

    const challenge_offset = challengeOffset.toString();

    circuitInputs = {
      pubkey,
      r,
      s,
      challenge,
      client_data_json,
      challenge_offset, 
      authenticator_data

    }
    return circuitInputs;
  }

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

  // challenge offset
  let challenge_index = client_data.toString().indexOf("challenge") + 12


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

  return getCircuitInputs(sig, pubkey, challenge, challenge_index, client_data, auth_data_bin);
}

async function do_generate() {
  const gen_inputs = await generate_inputs();
  return gen_inputs;
}

// If main
if (typeof require !== "undefined" && require.main === module) {
  // debug_file();
  const circuitInputs = do_generate().then((res) => {
    console.log("Writing to file...");
    fs.writeFileSync(`./webauthn.json`, JSON.stringify(res), { flag: "w" });
  }
  );
  // gen_test();
}