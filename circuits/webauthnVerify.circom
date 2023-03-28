pragma circom 2.0.3;

include "./sha.circom";
include "./QuinSelector.circom";
include "./base64.circom";

template WebAuthnVerify(k, max_challenge_bytes, max_client_json_bytes) {
  signal input pub_key[k]; 
  signal input signature[k];

  signal input challenge[max_challenge_bytes]; // options.challenge

  signal input client_data_json[max_client_json_bytes]; 
  signal input challenge_offset; // where the challenge is in the json, C.challenge

  // 11. Verify that the value of C.type is the string webauthn.get

  // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
  // options.challenge is the challenge the server originally generated
  // C.challenge is in the clientDataJson response from the client

    component id_equals[max_client_json_bytes];
    component ch_equals[max_challenge_bytes];

    // ignore
    // square max_challenge_bytes using quin selectors ? 
    // it's max_challenge_bytes * max_client_json_bytes if i do the shifting method
    for (var i = 0; i < max_client_json_bytes; i++) {
        id_equals[i] = GreaterEqThan(15);
        id_equals[i].in[0] <== i;
        id_equals[i].in[1] <== challenge_offset; 

        if (id_equals[i].out) {
          // check equality between C.challenge and options.challenge

          for (var j = 0; j < max_challenge_bytes; j++) {
            // TODO: is this i + j thing possible
            challenge[j] === client_data_json[i];
            i = i + 1;
          }
          // int challenge_idx = i - challenge_offset;

          // ch_equal = IsEqual();

          // component challenge_selector = QuinSelector(max_challenge_bytes);
          // // TODO: not sure if the way im passing in in is correct
          // challenge_selector.in = challenge;
          // challenge_selector.index = challenge_idx;

          // client_data_json[i] === challenge_selector.out;
        }
    }



}

component main = WebAuthnVerify(10, 10, 10);