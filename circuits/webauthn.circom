pragma circom 2.0.3;

include "./sha.circom";
// include "./QuinSelector.circom";
include "./base64.circom";
include "./ecdsa/ecdsa.circom";

template WebAuthnVerify(n, k, max_challenge, max_client_json, max_auth_data) {
  signal input pubkey[2][k]; 
  signal input r[k];
  signal input s[k];

  signal input challenge[max_challenge]; // options.challenge

  signal input client_data_json[max_client_json]; 
  signal input challenge_offset; // where the challenge is in the json, C.challenge
  // https://w3c.github.io/webauthn/#sctn-authenticator-data
  signal input authenticator_data[max_auth_data]; // 37 bytes or more, just do an array of 37*8 bits, decoded

  // 11. Verify that the value of C.type is the string webauthn.get

  // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
  // options.challenge is the challenge the server originally generated
  // C.challenge is in the clientDataJson response from the client

  // we are not actually doing any encoding here :))))) passing in non-encoded values
  // isolate where challenge domain is
  component challenge_eq[max_client_json];
  for (var i = 0; i < max_client_json; i++) {
    challenge_eq[i] = IsEqual();
    challenge_eq[i].in[0] <== i;
    challenge_eq[i].in[1] <== challenge_offset;
  }
  // shift C.challenge to beginning of json
  signal shifted_challenge[max_challenge][max_client_json];
  for (var i = 0; i < max_challenge; i++) {
    shifted_challenge[i][i] <== challenge_eq[i].out * client_data_json[i];
    for (var j = i + 1; j < max_client_json; j++) {
        shifted_challenge[i][j] <== shifted_challenge[i][j - 1] + client_data_json[j] * challenge_eq[j-i].out;
    }
  }

  // constrain the challenge with shifted_challenge
  for (var i = 0; i < max_challenge; i++) {
    challenge[i] === shifted_challenge[i][max_client_json - 1];
  }

  // 13. Verify that the value of C.origin matches the Relying Party's origin.

  // skipped 14 and 15

  // 16-17: Verify that the User Present and User Verified bit of the flags in authData is set.
  // just check bit 0 and bit 2 for user present and user verified

  // component auth_bits = Num2Bits(8);
  // we only need the 33rd bit of the authenticator data input
  // auth_bits.in = authenticator_data[32];

  // auth_bits.out[0] === 1;
  // auth_bits.out[2] === 1;

  authenticator_data[32 * 8] === 1;
  authenticator_data[32 * 8 + 2] === 1;

  // skip 18 since it is optional

  // 19 (compute hash), 20 Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.
  component hashed_client_data = Sha256Bytes(max_client_json);
  for (var i = 0; i < max_client_json; i++) {
    hashed_client_data.in_padded[i] <== client_data_json[i];
  }

  // TODO: check if this is right
  hashed_client_data.in_len_padded_bytes <== max_client_json;

  // TODO: we are using auth data as bits here
  // auth data as bits + 256 bits of sha
  var concat_len = max_auth_data + 256; 

  signal concatenated_json_auth[concat_len]; 
  signal temp[concat_len];
  component concat_eq[concat_len];
  // binary concatenation of authdata and hash
  for (var i = 0; i < concat_len; i++) {
    concat_eq[i] = GreaterEqThan(15);
    concat_eq[i].in[0] <== i;
    concat_eq[i].in[1] <== max_auth_data;
    var passed_auth = concat_eq[i].out;
    var non_passed_auth = 1 - concat_eq[i].out; 

    temp[i] <== (authenticator_data[i % max_auth_data] * non_passed_auth);
    concatenated_json_auth[i] <== (hashed_client_data.out[i % 256] * (passed_auth)) + temp[i];
  }

  // 20. ECDSA verify
  // hash concatenation before ecdsa
  component hashed_sig_msg = Sha256Bytes(concat_len);
  for (var i = 0; i < concat_len; i++) {
    hashed_sig_msg.in_padded[i] <== concatenated_json_auth[i];
  }
  // TODO: check if this is right
  hashed_sig_msg.in_len_padded_bytes <== concat_len;

  var msg_len = (256+n)\n;
  component base_msg[msg_len];
  for (var i = 0; i < msg_len; i++) {
    base_msg[i] = Bits2Num(n);
  }
  for (var i = 0; i < 256; i++) {
    base_msg[i\n].in[i%n] <== hashed_sig_msg.out[255 - i];
  }
  for (var i = 256; i < n*msg_len; i++) {
    base_msg[i\n].in[i%n] <== 0;
  }

  // signature verification
  // TODO: fix these values
  component ecdsa = ECDSAVerifyNoPubkeyCheck(n, k);
  
  for (var i = 0; i < k; i ++) {
    ecdsa.r[i] <== r[i];
    ecdsa.s[i] <== s[i];
    ecdsa.msghash[i] <== base_msg[i].out;
    ecdsa.pubkey[0][i] <== pubkey[0][i];
    ecdsa.pubkey[1][i] <== pubkey[1][i];
  }

  ecdsa.result === 1;

  // 21. do i need to do???

}

component main = WebAuthnVerify(64, 4, 100, 512, 512);