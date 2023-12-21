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