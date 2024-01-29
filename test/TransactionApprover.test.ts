import path = require('path');

import { expect, assert } from 'chai';
import { ethers } from 'hardhat';
import { sha256 } from '@noble/hashes/sha256';
import { generateCircuitInputs, uint8ArrayToBigInt } from './utils';
import { IERC20, MockERC20, TransactionApprover } from "../types"

import * as snarkjs from "snarkjs";
import { SignerWithAddress } from '@nomicfoundation/hardhat-ethers/signers';

function calculateChallenge(to: string, data: Buffer, nonce: bigint): Uint8Array {
  let to_buf = Buffer.from(to.substring(2), 'hex');
  let nonce_buf = Buffer.from(nonce.toString(16).padStart(64,'0'), 'hex');
  let buf = Buffer.concat([
    Buffer.concat([Buffer.alloc(32-to_buf.length).fill(0), to_buf]),
    data,
    nonce_buf
  ]);
  let hash = sha256(buf);
  // We chop off the highest order byte
  return hash.subarray(1, 32);
}

function get_calldata(token: IERC20, to: string, amount: bigint): string {
  return token.interface.encodeFunctionData('transfer', [to, amount]);
}

function proofToSolidityArgs(proof: snarkjs.Groth16Proof, args: snarkjs.PublicSignals): TransactionApprover.ProofArgsStruct {
  return {
    _pA: [proof.pi_a[0], proof.pi_a[1]],
    _pB: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
    _pC: [proof.pi_c[0], proof.pi_c[1]],

    pubSignals: args
  }
}

describe('TransactionApprover', async () => {
  let transactionApprover: TransactionApprover;
  let token: MockERC20
  let tokenAddr: string;
  let user: SignerWithAddress
  
  before(async () => {
    [user] = await ethers.getSigners();
    token = (await (await ethers.getContractFactory("MockERC20")).deploy("Token", "Test")) as unknown as MockERC20;
    tokenAddr = await token.getAddress();

    // Because the webauthn is generated outside of this repo, we must ensure that our test data is valid
    assert(tokenAddr === "0x5FbDB2315678afecb367f032d93F642f64180aa3");

    transactionApprover = (await (await ethers.getContractFactory("TransactionApprover")).deploy()) as unknown as TransactionApprover;
    await token.mint(await transactionApprover.getAddress(), 1000);
  })

  it('Test transacting', async () => {
    let x = uint8ArrayToBigInt(Buffer.from("vHTWVKxnKBZqRH5YSN2CRACDfe78MDKYAJV2ihClo_0", "base64url"));
    let y = uint8ArrayToBigInt(Buffer.from("7n-dVDPu-dJud6lqbyq_9YJWowLAidwk1880i5PhsHo", "base64url"));

    let to = "0xfc6956F2962005cfD17d1f9C6cd1EEb9B4E03468";
    let amount = 500n;
    let calldata = get_calldata(token as IERC20, to, amount);
    let challenge = Buffer.from(calculateChallenge(await token.getAddress(), Buffer.from(calldata.substring(2), 'hex'), 1n));

    let clientDataJSON = Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidXZ5Ym9MUjQ3NV9uVkFGRVVQR0lZQzZSa0ptamZfZGRGbkZGZjJsbmVRIiwib3JpZ2luIjoiaHR0cHM6Ly9wMjU2d2FsbGV0Lm9yZyIsImNyb3NzT3JpZ2luIjpmYWxzZSwidmlydHVhbF9hdXRoZW50aWNhdG9yIjoiR3JhbVRoYW5vcyAmIFVuaXZlcnNpdHkgb2YgUGlyYWV1cyJ9", 'base64url');
    let authData = Buffer.from("6wsaDxeDGfShVTbwFOadYF2xhcKegtyrwRShhvKRLWgFAABfFw", 'base64url');
    let signature = Buffer.from("MEQCIA51_-QOhxPgbxRXM9KJdc684hgyqSEXoT6zDELT3KkcAiBlYAlrjF4DZUwNgMIAL-c2g2FTOYlf2ikeau2vaS2CAQ", "base64url");

    let input = generateCircuitInputs(
      [x,y],
      signature,
      authData,
      clientDataJSON,
      challenge,
      64,
      256
    );

    expect(await token.balanceOf(await transactionApprover.getAddress())).gt(amount)

    let build_dir = path.join(__dirname, "../build/webauthn");
    let {proof, publicSignals} = await snarkjs.groth16.fullProve(input, path.join(build_dir, "webauthn_default_js", "webauthn_default.wasm"), path.join(build_dir, "webauthn_default.zkey"));
    let proofArgs = proofToSolidityArgs(proof, publicSignals);

    await transactionApprover.register([x,y]);

    const tx = await transactionApprover.execute(x, tokenAddr, calldata, 1n, proofArgs, {gasLimit: 30000000});

    expect(await token.balanceOf(to)).eq(amount);
  });
});