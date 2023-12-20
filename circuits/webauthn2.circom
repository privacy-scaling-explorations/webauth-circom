pragma circom 2.1.5;

include "./sha256flex.circom";
//include "./ecdsa/circuits/ecdsa.circom";
include "./webauthn_json_hardcodes.circom";

// Can the challenge simply be a hash of the tx data? (calldata, nonce, sender, gas, etc), which then the
// smart contract generates and passes as public input?
template WebAuthnVerify(n, k, max_auth_data) {
  /// Private Inputs
  signal input r[k];
  signal input s[k];
  signal input auth_data_num_bytes;
  signal input auth_data[max_auth_data]; // Each signal is 252 bits

  /// Public Inputs
  signal input pubkey[2][k];
  signal input challenge;   // Challenge is 252 bits as we chop off 4 bits of the hash of the tx data
  signal input origin;      // Should be padded to 212 bits
  signal input signCount;   // C.signCount (if we use this, should probably be public?)
  signal input rpId;
  //signal input rpIdHash[2];  // TODO: I think rpId and rpIdHash can be constants

  // 11. Verify that the value of C.type is the string webauthn.get
  // WE DO NOT NEED TO DO THIS, as this effects the generated hash that is signed

  // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
  // - NOT NEEDED as the tx data is the challenge

  // 13. Verify that the value of C.origin matches the Relying Party's origin.
  // - NOT NEEDED

  // 14. Verify that the value of C.tokenBinding.status matches the state of Token Binding 
  // for the TLS connection over which the attestation was obtained. 
  // If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id 
  // matches the base64url encoding of the Token Binding ID for the connection.
  // - NOT NEEDED

  // 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
  // - NOT NEEDED as we must assume client is hostile

  // 16. Verify that the User Present bit of the flags in authData is set.

  // 17. If user verification is required for this assertion, verify that the User Verified bit of the flags 
  // in authData is set.

  // 18. [Paraphrased] Extensions for processing that are irrelevant to us

  // 19. Let hash be the result of computing a hash over the cData using SHA-256.
  // Serialization: https://w3c.github.io/webauthn/#clientdatajson-serialization
  // Python: binascii.hexlify(b'{"type":')

  component client_data_hasher = Sha256(1024);
  // Convert the challenge and origin to bits
  component challenge_bits = Num2Bits(252);
  component origin_bits = Num2Bits(212);
  challenge_bits.in <== challenge; 
  origin_bits.in <== origin;
  
  var part1_bits[288] = get_json_part_1();
  var part2_bits[96] = get_json_part_2();
  var part3_bits[176] = get_json_part_3();
  for (var i = 0; i < 288; i++) client_data_hasher.in[i] <== part1_bits[i];
  for (var i = 0; i < 252; i++) client_data_hasher.in[288+i] <== challenge_bits.out[i];
  for (var i = 0; i < 96; i++) client_data_hasher.in[540+i] <== part2_bits[i];
  for (var i = 0; i < 212; i++) client_data_hasher.in[636+i] <== origin_bits[i];
  for (var i = 0; i < 176; i++) client_data_hasher.in[848+i] <== part3_bits[i];

  // 20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData 
  // and hash.

  //var auth_data_num_bits = auth_data_num_bytes*8;
  //var concatenated[256+auth_data_num_bits];

  component message_hasher = Sha256(256+auth_data_num_bits);
  
}

component main = Sha256Flexible(512);