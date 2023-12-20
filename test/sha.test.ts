import path = require('path');

import { expect, assert } from 'chai';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { SignatureType } from '@noble/curves/abstract/weierstrass';
import { bytesToHex as toHex } from '@noble/hashes/utils';
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

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

describe.only('Variable sha256 circuit', async () => {
  let sha_circuit: any;
  before(async () => {
    sha_circuit = await wasm_tester(path.join(__dirname, 'circuits', 'test_shavar.circom'));
  })

  it('Sha256', async () => {
    let input = Buffer.alloc(128).fill(0);
    input[0] = 1;
    let witness = await sha_circuit.calculateWitness({in: bufferToBigIntArray(Buffer.from(bufferTobitArray(input))), num_bytes: 1});
    //let witness2 = await (await wasm_tester(path.join(__dirname, 'circuits', 'test_sha256_circomlib.circom'))).calculateWitness({in: bufferToBigIntArray( Buffer.from(bufferTobitArray(input))) });
    console.log(bitArrayTobuffer(witness.slice(1,257)).toString('hex'));
    //console.log(bitArrayTobuffer(witness2.slice(1,257)).toString('hex'));
    console.log(toHex(sha256(Buffer.from([1]))));

    console.log(input);
    console.log(Buffer.from([1,0]));
  });

  it('Verification', async () => {
    console.log("yo");
  })
})