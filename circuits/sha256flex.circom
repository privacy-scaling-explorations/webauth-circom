pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/sha256/constants.circom";
include "../node_modules/circomlib/circuits/sha256/sha256compression.circom";
include "../node_modules/circomlib/circuits/mux2.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Sha256Input(nBits) {
  assert(nBits % 64 == 0);
  signal input num_bytes;
  var nBlocks = ((nBits + 64)\512)+1;
  signal input in[nBlocks*512];
  signal output paddedIn[nBlocks*512];

  var num_bits_in = num_bytes*8;
  var nBlocks_in = ((num_bits_in + 64)\512)+1;

  component length_bits = Num2Bits(64);
  length_bits.in <== num_bits_in;

  component decider_lt[nBlocks*512];
  component decider_eq[nBlocks*512];
  component decider_length[nBlocks];
  component muxers[nBlocks*64];

  component constrain_lt[nBlocks];
  component constrain_gt[nBlocks];
  
  for (var k = 0; k < nBlocks-1; k++) {

    // The first 448 bits will always be either input puts, the `1` delimiter bit, or 0
    for (var i = 0; i < 448; i++) {
      decider_lt[k*512+i] = LessThan(64);
      decider_lt[k*512+i].in[0] <== k*512+i;
      decider_lt[k*512+i].in[1] <== num_bits_in;

      decider_eq[k*512+i] = IsEqual();
      decider_eq[k*512+i].in[0] <== k*512+i;
      decider_eq[k*512+i].in[1] <== num_bits_in;

      paddedIn[k*512+i] <== 1*decider_eq[k*512+i].out + (in[k*512+i] * decider_lt[k*512+i].out);
    }

    // We need to determine if we are in the final block, which means the last 64 bits should be the counter
    decider_length[k] = IsEqual();
    decider_length[k].in[0] <== k;
    decider_length[k].in[1] <-- nBlocks_in-1;

    // Because the number of bits is from an input signal, we can only constrain the number of blocks by less than and greater than components
    constrain_lt[k] = LessThan(64);
    constrain_lt[k].in[0] <== decider_length[k].in[1]*512;
    constrain_lt[k].in[1] <== num_bits_in+64;
    constrain_lt[k].out === 1;
    constrain_gt[k] = GreaterEqThan(64);
    constrain_gt[k].in[0] <== decider_length[k].in[1]*512;
    constrain_gt[k].in[1] <== num_bits_in-512;
    constrain_gt[k].out === 1;

    for (var i = 448; i < 512; i++) {
      decider_lt[k*512+i] = LessThan(64);
      decider_lt[k*512+i].in[0] <== k*512+i;
      decider_lt[k*512+i].in[1] <== num_bits_in;

      decider_eq[k*512+i] = IsEqual();
      decider_eq[k*512+i].in[0] <== k*512+i;
      decider_eq[k*512+i].in[1] <== num_bits_in;

      muxers[k*64+i-448] = Mux2();
      muxers[k*64+i-448].c[0] <== 0;
      muxers[k*64+i-448].c[1] <== in[k*512];
      muxers[k*64+i-448].c[2] <== length_bits.out[63-(i-448)];
      muxers[k*64+i-448].c[3] <== 1;

      muxers[k*64+i-448].s[0] <== decider_eq[k*512+i].out + decider_lt[k*512+i].out;
      muxers[k*64+i-448].s[1] <== decider_eq[k*512+i].out + decider_length[k].out;

      paddedIn[k*512+i] <== muxers[k*64+i-448].out;
    }
  }
}

template Sha256Flexible(nBits) {
  assert(nBits % 512 == 0);
  signal input num_bytes;
  signal output out[256];

  var nBlocks = ((nBits + 64)\512)+1;
  signal input in[nBits];

  var num_bits_in = num_bytes*8;
  var nBlocks_in = ((num_bits_in + 64)\512)+1;

  signal paddingInput[nBlocks*512];
  for (var i = 0; i < nBits; i++) paddingInput[i] <== in[i];
  for (var i = 0; i < 512; i++) paddingInput[i+nBits] <== 0;

  component padding = Sha256Input(nBits);
  padding.num_bytes <== num_bytes;
  padding.in <== paddingInput;

  signal bits[nBlocks*512] <== padding.paddedIn;

  component hasher = Sha256Function(nBlocks);
  hasher.in <== bits;
  hasher.endBlock <-- nBlocks_in-1;// FIXME THIS IS UNCONSTRAINED
  out <== hasher.out;
}

template Sha256Function(nBlocks) {
  signal input in[nBlocks*512];
  signal input endBlock;
  signal output out[256];

  component ha0 = H(0);
  component hb0 = H(1);
  component hc0 = H(2);
  component hd0 = H(3);
  component he0 = H(4);
  component hf0 = H(5);
  component hg0 = H(6);
  component hh0 = H(7);

  component sha256compression[nBlocks];

  for (var i=0; i<nBlocks; i++) {
    sha256compression[i] = Sha256compression() ;
    if (i==0) {
      for (var k=0; k<32; k++ ) {
        sha256compression[i].hin[0*32+k] <== ha0.out[k];
        sha256compression[i].hin[1*32+k] <== hb0.out[k];
        sha256compression[i].hin[2*32+k] <== hc0.out[k];
        sha256compression[i].hin[3*32+k] <== hd0.out[k];
        sha256compression[i].hin[4*32+k] <== he0.out[k];
        sha256compression[i].hin[5*32+k] <== hf0.out[k];
        sha256compression[i].hin[6*32+k] <== hg0.out[k];
        sha256compression[i].hin[7*32+k] <== hh0.out[k];
        }
    } else {
      for (var k=0; k<32; k++ ) {
        sha256compression[i].hin[32*0+k] <== sha256compression[i-1].out[32*0+31-k];
        sha256compression[i].hin[32*1+k] <== sha256compression[i-1].out[32*1+31-k];
        sha256compression[i].hin[32*2+k] <== sha256compression[i-1].out[32*2+31-k];
        sha256compression[i].hin[32*3+k] <== sha256compression[i-1].out[32*3+31-k];
        sha256compression[i].hin[32*4+k] <== sha256compression[i-1].out[32*4+31-k];
        sha256compression[i].hin[32*5+k] <== sha256compression[i-1].out[32*5+31-k];
        sha256compression[i].hin[32*6+k] <== sha256compression[i-1].out[32*6+31-k];
        sha256compression[i].hin[32*7+k] <== sha256compression[i-1].out[32*7+31-k];
      }
    }

    for (var k=0; k<512; k++) {
      sha256compression[i].inp[k] <== in[i*512+k];
    }
  }

  component blockChooser[nBlocks];
  component summer[256];
  for (var i = 0; i < 256; i++) summer[i] = Sum(nBlocks);
  for (var i = 0; i < nBlocks; i++) {
    blockChooser[i] = IsEqual();
    blockChooser[i].in[0] <== i;
    blockChooser[i].in[1] <== endBlock;

    for (var k=0; k<256; k++) {
      summer[k].in[i] <== sha256compression[i].out[k] * blockChooser[i].out;
    }
  }

  for (var k = 0; k < 256; k++) {
    out[k] <== summer[k].out;
  }
}

// Sum over all the inputs
template Sum(n) {
  signal input in[n];
  signal output out;

  signal sum[n];
  sum[0] <== in[0];
  for (var i = 1; i < n; i++) {
    sum[i] <== sum[i-1] + in[i];
  }

  out <== sum[n-1];
}