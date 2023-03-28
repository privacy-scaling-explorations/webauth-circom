pragma circom 2.0.3;

include "./sha.circom";
// include "./QuinSelector.circom";
include "./base64.circom";

template WebAuthnVerify(k, max_challenge_bytes, max_client_json_bytes, max_auth_data) {
//   signal input pub_key[k]; 
//   signal input signature[k];

  signal input encoded_challenge[max_challenge_bytes]; // encoded options.challenge

  signal input client_data_json[max_client_json_bytes]; 
  signal input challenge_offset; // where the challenge is in the json, C.challenge
  // https://w3c.github.io/webauthn/#sctn-authenticator-data
  signal input authenticator_data[max_auth_data]; // 37 bytes or more

  // 11. Verify that the value of C.type is the string webauthn.get

  // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
  // options.challenge is the challenge the server originally generated
  // C.challenge is in the clientDataJson response from the client

  // isolate where challenge domain is
  component challenge_eq[max_client_json_bytes];
  for (var i = 0; i < max_client_json_bytes; i++) {
    challenge_eq[i] = IsEqual();
    challenge_eq[i].in[0] <== i;
    challenge_eq[i].in[1] <== challenge_offset;
  }
  // shift C.challenge to beginning of json
  var shifted_challenge[max_challenge_bytes][max_client_json_bytes];
  for (var i = 0; i < max_challenge_bytes; i++) {
    shifted_challenge[i][i] <== challenge_offset * client_data_json[i];
    for (var j = i + 1; j < max_client_json_bytes; j++) {
        shifted_challenge[i][j] <== shifted_challenge[i][j - 1] + client_data_json[j] * challenge_eq[j-i];
    }
  }

  // constrain the found email domain and passed email domain
  for (var i = 0; i < max_challenge_bytes; i++) {
    challenge[i] === shifted_challenge[i][max_client_json_bytes - 1];
  }

  // 13. Verify that the value of C.origin matches the Relying Party's origin.

  // skipped 14 and 15

  // 16-17: Verify that the User Present and User Verified bit of the flags in authData is set.
  // just check bit 0 and bit 2 for user present and user verified
  component auth_bits = Num2Bits(8);
  // we only need the 33rd bit of the authenticator data input
  auth_bits.in = authenticator_data[32];

  auth_bits.out[0] === 1;
  auth_bits.out[2] === 1;

  // skip 18 since it is optional

  // 19 (compute hash), 20 Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
  component hashed_client_data = Sha256Bytes(max_client_json_bytes);
  for (var i = 0; i < max_client_json_bytes; i++) {
    hashed_client_data.in_padded[i] <== client_data_json[i];
  }

  // TODO: check if this is right
  hashed_client_data.in_len_padded_bytes <== max_client_json_bytes;

  // concatenate authdata and hash

}

component main = WebAuthnVerify(10, 10, 10);