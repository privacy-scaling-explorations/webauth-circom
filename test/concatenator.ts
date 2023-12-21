import path = require('path');

import { bytesToHex as toHex } from '@noble/hashes/utils';
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;
import {BigIntArrayToBuffer, bitArrayTobuffer, bufferToBigIntArray, bufferToBitArray} from './utils';
import { expect } from 'chai';

describe.only('Concatenate arrays', async () => {
  let concatenator_circuit: any;
  before(async () => {
    concatenator_circuit = await wasm_tester(path.join(__dirname, 'circuits', 'test_concatenator.circom'));
  })

  it('Min = 8, Max = 16, Second = 24 (bits)', async () => {
    let first = Buffer.alloc(2).fill(0);
    first[0] = 15;
    let second = Buffer.alloc(3).fill(3);

    let witness = await concatenator_circuit.calculateWitness({
      first: bufferToBigIntArray(Buffer.from(bufferToBitArray(first))),
      second: bufferToBigIntArray(Buffer.from(bufferToBitArray(second))),
      first_size: 8
    });

    console.log(witness.slice(1,40));

    expect(bitArrayTobuffer(witness.slice(1,40))).eql(Buffer.concat([
      first.subarray(0,1),
      second,
      Buffer.alloc(1)
    ]));

  });

  it('Min = 8, Max = 16, Second = 24 (bytes)', async () => {
    let first = Buffer.alloc(16).fill(0);
    first[0] = 15;
    first[9] = 20;
    let second = Buffer.alloc(24).fill(3);

    let witness = await concatenator_circuit.calculateWitness({
      first: bufferToBigIntArray(first),
      second: bufferToBigIntArray(second),
      first_size: 10
    });

    expect(BigIntArrayToBuffer(witness.slice(1,40))).eql(Buffer.concat([
      first.subarray(0,10),
      second,
      Buffer.alloc(5)
    ]));
  })
})