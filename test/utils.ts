import { p256 } from "@noble/curves/p256";

export function bufferToBitArray(b: Buffer) {
  const res = [];
  for (let i=0; i<b.length; i++) {
      for (let j=0; j<8; j++) {
          res.push((b[i] >> (7-j) &1));
      }
  }
  return res;
}

export function bitArrayTobuffer(a: number[] | bigint[]) {
  const len = Math.floor((a.length -1 )/8)+1;
  const b = Buffer.alloc(len);

  for (let i=0; i<a.length; i++) {
      const p = Math.floor(i/8);
      b[p] = b[p] | (Number(a[i]) << ( 7 - (i%8)  ));
  }
  return b;
}

export function bufferToBigIntArray(arr: Buffer): bigint[] {
  let res: bigint[] = [];
  arr.forEach((x) => res.push(BigInt(x)));

  return res;
}

export function BigIntArrayToBuffer(arr: bigint[]): Buffer {
  let res =  Buffer.alloc(arr.length);
  arr.forEach((x, i) => res[i] = Number(x));

  return res;
}

export function bigint_to_registers(x: bigint, n: number, k: number): bigint[] {
  let mod: bigint = 1n;
  for (var idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret: bigint[] = [];
  var x_temp: bigint = x;
  for (var idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod);
    x_temp = x_temp / mod;
  }
  return ret;
}

export function bigint_to_registers_string(x: bigint, n: number, k: number): string[] {
  let registers = bigint_to_registers(x,n,k);
  let res: string[] = [];
  for (var r of registers) {
    res.push(r.toString());
  }
  return res;
}

export function uint8ArrayToBigInt(x: Uint8Array): bigint {
  return BigInt('0x'+Buffer.from(x).toString('hex'));
}

export type WebauthnCircuitInput = {
  r: bigint[]
  s: bigint[]
  auth_data: bigint[],
  auth_data_num_bytes: bigint,
  client_data: bigint[],
  client_data_num_bytes: bigint,

  pubkey: bigint[][],
  challenge: bigint,
  // origin: bigint,
  // signCount: bigint,
  // rpId: bigint
}

export function generateCircuitInputs(
  pubkey: bigint[],
  sig: Buffer,
  authenticatorData: Buffer,
  clientDataJSON: Buffer,
  challenge: Buffer,
  authDaataSize: number,
  clientDataSize: number,
): WebauthnCircuitInput {
  let sig_decoded = p256.Signature.fromDER(sig.toString('hex'));
  return {
    r: bigint_to_registers(sig_decoded.r, 43, 6),
    s: bigint_to_registers(sig_decoded.s, 43, 6),
    auth_data: bufferToBigIntArray(Buffer.concat([authenticatorData], authDaataSize)),
    auth_data_num_bytes: BigInt(authenticatorData.length),
    client_data: bufferToBigIntArray(Buffer.concat([clientDataJSON], clientDataSize)),
    client_data_num_bytes: BigInt(clientDataJSON.length),

    pubkey: [bigint_to_registers(pubkey[0], 43, 6), bigint_to_registers(pubkey[1], 43, 6)],
    challenge: BigInt('0x'+challenge.toString('hex'))
  }
}