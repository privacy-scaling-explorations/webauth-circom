import path = require('path');

import { expect, assert } from 'chai';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { SignatureType } from '@noble/curves/abstract/weierstrass';
import { bytesToHex as toHex } from '@noble/hashes/utils';
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

// export function toHex(bytes: Uint8Array): string {
//   return Array.from(bytes || [])
//     .map((b) => HEX_STRINGS[b >> 4] + HEX_STRINGS[b & 15])
//     .join("");
// }

// NOTE: Does not check if input elements are binary
// function binaryArrayToHex(arr: bigint[]): string {
//   // let result = 0n;
//   // let n = 1n;
//   // for (var i =0; i < arr.length; i++) {
//   //   result += arr[i] * n;
//   //   n *= 2n;
//   // }

//   // return result.toString(16);
//   const b: Buffer = Buffer.alloc(32);
//   for (let i = 0; i < arr.length; i++) {
//     const p = Math.floor(i / 8);
//     b[p] = b[p] | (Number(arr[i]) << (7 - (i % 8)));
//   }

//   return b.toString('hex');
// }

// function uint8ArrayToBigIntArray(arr: Uint8Array): bigint[] {
//   let res: bigint[] = [];
//   arr.forEach((x) => res.push(BigInt(x)));

//   return res;
// }

// function uint8ArrayToBinaryInput(arr: Uint8Array): bigint[] {
//   let res: bigint[] = [];
//   arr.forEach((x) => {
//     for (let i = 0; i < 8; i++) {
//       res.push(BigInt(x & 2**i));
//     }
    
//   });

//   return res;
// }
function bufferTobitArray(b: Buffer) {
  const res = [];
  for (let i=0; i<b.length; i++) {
      for (let j=0; j<8; j++) {
          res.push((b[i] >> (7-j) &1));
      }
  }
  return res;
}

function bitArrayTobuffer(a: number[] | bigint[]) {
  const len = Math.floor((a.length -1 )/8)+1;
  const b = Buffer.alloc(len);

  for (let i=0; i<a.length; i++) {
      const p = Math.floor(i/8);
      b[p] = b[p] | (Number(a[i]) << ( 7 - (i%8)  ));
  }
  return b;
}

function bufferToBigIntArray(arr: Buffer): bigint[] {
  let res: bigint[] = [];
  arr.forEach((x) => res.push(BigInt(x)));

  return res;
}

describe('Webauthn circuit', async () => {
  let sha_circuit: any;
  before(async () => {
    sha_circuit = await wasm_tester(path.join(__dirname, 'circuits', 'test_sha256.circom'));
  })

  it('Sha256', async () => {
    //let input = new Array(512).fill(0n);
    //let input: ArrayBuffer = new ArrayBuffer(128);
    //let input_view = new Uint8Array(input);
    // for (let i =0; i < 128; i++) {
    //   input_view[i] = 1;
    // }

    // let witness = await sha_circuit.calculateWitness({in_padded: uint8ArrayToBigIntArray(input_view), in_len_padded_bytes: 128});
    // let witness2 = await (await wasm_tester(path.join(__dirname, 'circuits', 'test_sha256_circomlib.circom'))).calculateWitness({in: uint8ArrayToBinaryInput(input_view)});

    // let output = witness.slice(1,257);
    // console.log(binaryArrayToHex(output));
    // console.log(binaryArrayToHex(witness2.slice(1,257))); // TODO: This is wrong bc circomlib takes in bits not bytes
    // console.log(toHex(sha256(input_view)));

    let input = Buffer.alloc(128).fill(255);
    let witness = await sha_circuit.calculateWitness({in_padded: bufferToBigIntArray(input), in_len_padded_bytes: 128});
    let witness2 = await (await wasm_tester(path.join(__dirname, 'circuits', 'test_sha256_circomlib.circom'))).calculateWitness({in: bufferToBigIntArray( Buffer.from(bufferTobitArray(input))) });
    console.log(bitArrayTobuffer(witness.slice(1,257)).toString('hex'));
    console.log(bitArrayTobuffer(witness2.slice(1,257)).toString('hex'));
    console.log(toHex(sha256(input)));
  });

  it('Verification', async () => {
    console.log("yo");
  })
})