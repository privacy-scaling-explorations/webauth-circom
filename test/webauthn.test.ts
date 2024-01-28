import path = require('path');
import * as fs from 'fs';

import { expect, assert } from 'chai';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { WebauthnCircuitInput, bigint_to_registers, bufferToBigIntArray, generateCircuitInputs, uint8ArrayToBigInt } from './utils';
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

describe('Webauthn circuit', async () => {
  // TODO FIXME: The clientData in this example data does NOT properly follow the serialization detailed in 5.8.1.1
  // the keys are not the right order
  // let x_str = "QonEgBTiNoL01zaKpgSV43wL69beeQkkgaygv_Jgmgk";
  // let y_str = "9KaOWB8Is976nwusLUkGk-xr4AnUBkGEUNDqS8pgOxc";
  // let clientDataJSON_str = "eyJjaGFsbGVuZ2UiOiJvczBHSzc4MVloMHFlQ29CZkhNTWpVQmo3ejgiLCJvcmlnaW4iOiJodHRwczovL3BzdGVuaXVzdWJpLmdpdGh1Yi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ"
  // let authenticatorData_str = "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEBAAAAIg"
  // let signature_str = "MEYCIQCHgyWh4jLKeaIBKNRcxoMeqZiNYa789xbfb_bYV35N_wIhAIewPLTTOOQE35NwxuewzV7PqTttLH_rhT32EeshaPUW"

  let x_str = "Oc1XdeNT5EMBLPSF_D1RhoTNuHJ6LnDSimYF62dHzcM";
  let y_str = "5FE62hmKu-RCNPbtjpQLPF2rkJUFEs-GlP9ZziJuJA8";
  let clientDataJSON_str = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiV1RrLXU5VnhVeU1vc2dubVMzdGh3X1ZhU2ZzIiwib3JpZ2luIjoiaHR0cHM6Ly9wc3Rlbml1c3ViaS5naXRodWIuaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ"
  let authenticatorData_str = "LNeTz6C0GMu_DqhSIoYH2el7Mz1NsKQQF3Zq9ruMdVEBAAAAJg"
  let signature_str = "MEYCIQD9WeQSdfyrKCv3CwWobEQHhzAULV0E0Uf7ZAzA1w3AHwIhAOsEOzyLgx00OZpHVWSpsUpYyOe3UHKI_TGliNILX_tC"
  let challenge_str = "WTk-u9VxUyMosgnmS3thw_VaSfs"

  let x = uint8ArrayToBigInt(Buffer.from(x_str,"base64url"));
  let y = uint8ArrayToBigInt(Buffer.from(y_str, "base64url"));
  let pubkey = new p256.ProjectivePoint(x, y, 1n);
  let sig = Buffer.from(signature_str, "base64url");
  let clientDataJSON = Buffer.from(clientDataJSON_str, "base64");
  let authenticatorData = Buffer.from(authenticatorData_str,"base64url");
  
  // The challenge is compared in the circuit as its Base64URL representation.
  let challenge = Buffer.from(challenge_str, 'base64url');

  let webauthn_circuit: any;
  before(async () => {
    webauthn_circuit = await wasm_tester(path.join(__dirname, 'circuits', 'test_webauthn64_20.circom'));
  })

  /// Test the normal P-256 verification over the test data
  it('Test webauthn vanilla verification', async () => {
    let hash = sha256(clientDataJSON);
    let msg_hash = Buffer.from(sha256(Buffer.concat([authenticatorData, hash])));
    //console.log(msg_hash.toString('hex'));
  
    let res = p256.verify(sig.toString('hex'), msg_hash.toString('hex'), pubkey.toHex());
    assert(res == true);
  })

  it('Circuit verification', async () => {
    let input = generateCircuitInputs(
      [x,y],
      sig,
      authenticatorData,
      clientDataJSON,
      challenge,
      64,
      256
    );

    //fs.writeFileSync(`./webauthn.json`, JSON.stringify(input), { flag: "w" });

    await webauthn_circuit.calculateWitness(input);
    
  });
})