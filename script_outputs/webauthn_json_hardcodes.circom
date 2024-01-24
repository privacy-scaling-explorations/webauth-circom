pragma circom 2.1.5;

// return {"type":"webauthn.get","challenge":"
function get_json_part_1() {
  var bytes[36];
  bytes[0] = 123;
  bytes[1] = 34;
  bytes[2] = 116;
  bytes[3] = 121;
  bytes[4] = 112;
  bytes[5] = 101;
  bytes[6] = 34;
  bytes[7] = 58;
  bytes[8] = 34;
  bytes[9] = 119;
  bytes[10] = 101;
  bytes[11] = 98;
  bytes[12] = 97;
  bytes[13] = 117;
  bytes[14] = 116;
  bytes[15] = 104;
  bytes[16] = 110;
  bytes[17] = 46;
  bytes[18] = 103;
  bytes[19] = 101;
  bytes[20] = 116;
  bytes[21] = 34;
  bytes[22] = 44;
  bytes[23] = 34;
  bytes[24] = 99;
  bytes[25] = 104;
  bytes[26] = 97;
  bytes[27] = 108;
  bytes[28] = 108;
  bytes[29] = 101;
  bytes[30] = 110;
  bytes[31] = 103;
  bytes[32] = 101;
  bytes[33] = 34;
  bytes[34] = 58;
  bytes[35] = 34;
  return bytes;
}

// return ","origin":"
function get_json_part_2() {
  var bytes[12];
  bytes[0] = 34;
  bytes[1] = 44;
  bytes[2] = 34;
  bytes[3] = 111;
  bytes[4] = 114;
  bytes[5] = 105;
  bytes[6] = 103;
  bytes[7] = 105;
  bytes[8] = 110;
  bytes[9] = 34;
  bytes[10] = 58;
  bytes[11] = 34;
  return bytes;
}

// return ","crossOrigin":false}
function get_json_part_3() {
  var bytes[22];
  bytes[0] = 34;
  bytes[1] = 44;
  bytes[2] = 34;
  bytes[3] = 99;
  bytes[4] = 114;
  bytes[5] = 111;
  bytes[6] = 115;
  bytes[7] = 115;
  bytes[8] = 79;
  bytes[9] = 114;
  bytes[10] = 105;
  bytes[11] = 103;
  bytes[12] = 105;
  bytes[13] = 110;
  bytes[14] = 34;
  bytes[15] = 58;
  bytes[16] = 102;
  bytes[17] = 97;
  bytes[18] = 108;
  bytes[19] = 115;
  bytes[20] = 101;
  bytes[21] = 125;
  return bytes;
}

