import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { IERC20, IERC20__factory } from '../types';
import { BaseContract } from 'ethers';

function calculateChallenge(to: string, data: Buffer, nonce: bigint): Uint8Array {
  let to_buf = Buffer.from(to.substring(2), 'hex');
  let nonce_buf = Buffer.from(nonce.toString(16).padStart(64,'0'), 'hex');
  let buf = Buffer.concat([
    Buffer.concat([Buffer.alloc(32-to_buf.length).fill(0), to_buf]),
    data,
    nonce_buf
  ]);
  let hash = sha256(buf);
  console.log(Buffer.from(hash).toString('hex'));
  // We chop off the highest order byte
  return hash.subarray(1, 32);
}

function get_calldata(token: IERC20, to: string, amount: bigint): string {
  return token.interface.encodeFunctionData('transfer', [to, amount]);
}

async function generateProof() {
  let pubkey_x = Buffer.from("vHTWVKxnKBZqRH5YSN2CRACDfe78MDKYAJV2ihClo_0", "base64url");
  let pubkey_y = Buffer.from("7n-dVDPu-dJud6lqbyq_9YJWowLAidwk1880i5PhsHo", "base64url");

  let to = "0xfc6956F2962005cfD17d1f9C6cd1EEb9B4E03468";
  let token = IERC20__factory.connect("0x5FbDB2315678afecb367f032d93F642f64180aa3");
  let amount = 500n;

  let calldata = get_calldata(token, to, amount);
  let challenge = Buffer.from(calculateChallenge(await token.getAddress(), Buffer.from(calldata.substring(2), 'hex'), 1n));

  console.log('calldata', calldata);
  console.log('challenge', '0x'+ challenge.toString('hex'), '(', challenge.toString('base64url'), ')');
  console.log(Uint8Array.from(challenge));
  
  let clientDataJSON = Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidXZ5Ym9MUjQ3NV9uVkFGRVVQR0lZQzZSa0ptamZfZGRGbkZGZjJsbmVRIiwib3JpZ2luIjoiaHR0cHM6Ly9wMjU2d2FsbGV0Lm9yZyIsImNyb3NzT3JpZ2luIjpmYWxzZSwidmlydHVhbF9hdXRoZW50aWNhdG9yIjoiR3JhbVRoYW5vcyAmIFVuaXZlcnNpdHkgb2YgUGlyYWV1cyJ9", "base64");
  let authData = Buffer.from("6wsaDxeDGfShVTbwFOadYF2xhcKegtyrwRShhvKRLWgFAABfFw", 'base64');
  let signature = Buffer.from("MEQCIA51_-QOhxPgbxRXM9KJdc684hgyqSEXoT6zDELT3KkcAiBlYAlrjF4DZUwNgMIAL-c2g2FTOYlf2ikeau2vaS2CAQ", "base64url");
  let sig_decoded = p256.Signature.fromDER(signature.toString('hex'));

}

generateProof()