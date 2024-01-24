pragma circom 2.1.5;

include "../node_modules/circomlib/circuits/comparators.circom";

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

// Convert a signal to a byte array. n is the number of bits of the signal
template to_byte_array(n) {
  assert(n % 8 == 0);
  signal input in;
  signal output out[n/8];

  component numify = Num2Bits(n);
  numify.in <== in;

  component nummers[n/8];
  for (var i = 0; i < n/8; i++) {
    nummers[i] = Bits2Num(8);
    for (var j = 0; j < 8; j++) {
      nummers[i].in[j] <== numify.out[i*8+j];
    }
    out[i] <== nummers[i].out;
  }
}

// Concatanate two arrays: The first array which is in size of [min_first,max_first] and a second array with static size
template concatenate_arrays(min_first, max_first, size_second) {
  signal input first[max_first];      // Input as bits
  signal input second[size_second];   // Input as bits
  signal input first_size;            // Size in bits

  var total_size = max_first + size_second;
  signal output out[total_size];

  // Put the bits that will always be from the first
  for (var i = 0; i < min_first; i++) out[i] <== first[i];

  //var bits_left = total_size-min_first;
  var possible_first = max_first-min_first; // The number of bits that can be either apart of first or second
  component in_first[possible_first];
  component summers[possible_first];

  // Put the bits that can be either from first or second
  for (var i=0; i < possible_first; i++) {
    in_first[i] = LessThan(64);
    in_first[i].in[0] <== i+min_first;
    in_first[i].in[1] <== first_size;

    summers[i] = Sum(size_second);
    for (var j = 0; j < size_second; j++) {
      var isEq = IsEqual()([first_size-min_first+j, i]);
      summers[i].in[j] <== isEq*second[j];
    }

    out[min_first+i] <== (in_first[i].out * first[i+min_first]) + summers[i].out;
  }

  // Put the bits that are either from the second or 0 padding
  component summers2[total_size-max_first];
  for (var i=0; i < total_size-max_first; i++) {
    summers2[i] = Sum(size_second);
    for (var j = 0; j < size_second; j++) {
      var isEq = IsEqual()([first_size-min_first+j, i+possible_first]);
      summers2[i].in[j] <== isEq*second[j];
    }

    out[i+max_first] <== summers2[i].out;
  }
}