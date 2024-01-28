pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mux2.circom";

function output_size(N) {
    var M = 4*N\3;
    if (N % 3 != 0) {
        M += 1;
    }
    return M;
}

template Base64Encode(N) {
    var M = output_size(N);
    signal input in[N];
    signal output out[M];

    component bits[N];
    component b64_character[M];
    for (var i = 0; i < N; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== in[i];
    }

    var full_limbs = N\3;
    for (var i = 0; i < full_limbs; i++) {
        var first[6];
        for (var j = 0; j < 6; j++) first[5-j] = bits[i*3].out[7-j];

        var second[6];
        second[5] = bits[i*3].out[1];
        second[4] = bits[i*3].out[0];
        for (var j = 0; j < 4; j++) second[3-j] = bits[i*3+1].out[7-j];

        var third[6];
        for (var j = 0; j < 4; j++) third[5-j] = bits[i*3+1].out[3-j];
        third[1] = bits[i*3+2].out[7];
        third[0] = bits[i*3+2].out[6];

        var fourth[6];
        for (var j = 0; j < 6; j++) fourth[5-j] = bits[i*3+2].out[5-j];

        b64_character[i*4] = Bits2Num(6);
        b64_character[i*4].in <== first;

        b64_character[i*4+1] = Bits2Num(6);
        b64_character[i*4+1].in <== second;

        b64_character[i*4+2] = Bits2Num(6);
        b64_character[i*4+2].in <== third;

        b64_character[i*4+3] = Bits2Num(6);
        b64_character[i*4+3].in <== fourth;

        out[i*4] <== encodeCharacter()(b64_character[i*4].out);
        out[i*4+1] <== encodeCharacter()(b64_character[i*4+1].out);
        out[i*4+2] <== encodeCharacter()(b64_character[i*4+2].out);
        out[i*4+3] <== encodeCharacter()(b64_character[i*4+3].out);
    }

    var full_consumed = 3*full_limbs;
    if (N-full_consumed == 1) {
        var first[6];
        for (var j = 0; j < 6; j++) first[5-j] = bits[N-1].out[7-j];
        b64_character[M-2] = Bits2Num(6);
        b64_character[M-2].in <== first;

        var second[6];
        for (var j = 0; j < 2; j++) second[5-j] = bits[N-1].out[1-j];
        second[2] = 0;
        second[3] = 0;
        second[4] = 0;
        second[5] = 0;

        b64_character[M-1] = Bits2Num(6);
        b64_character[M-1].in <== second;

        out[M-2] <== encodeCharacter()(b64_character[M-2].out);
        out[M-1] <== encodeCharacter()(b64_character[M-1].out);
    } else if (N-full_consumed == 2) {
        var first[6];
        for (var j = 0; j < 6; j++) first[5-j] = bits[N-2].out[7-j];
        b64_character[M-3] = Bits2Num(6);
        b64_character[M-3].in <== first;

        var second[6];
        for (var j = 0; j < 2; j++) second[5-j] = bits[N-2].out[1-j];
        for (var j = 0; j < 4; j++) second[3-j] = bits[N-1].out[7-j];
        b64_character[M-2] = Bits2Num(6);
        b64_character[M-2].in <== second;

        var third[6];
        for (var j = 0; j < 4; j++) third[5-j] = bits[N-1].out[3-j];
        third[0] = 0;
        third[1] = 0;
        b64_character[M-1] = Bits2Num(6);
        b64_character[M-1].in <== third;

        out[M-3] <== encodeCharacter()(b64_character[M-3].out);
        out[M-2] <== encodeCharacter()(b64_character[M-2].out);
        out[M-1] <== encodeCharacter()(b64_character[M-1].out);
    }
}


template encodeCharacter() {
    signal input in;
    signal output out;

    component lt_Z = LessThan(6);
    lt_Z.in[0] <== in;
    lt_Z.in[1] <== 26;

    component lt_z = LessThan(6);
    lt_z.in[0] <== in;
    lt_z.in[1] <== 52;

    component lt_9 = LessThan(6);
    lt_9.in[0] <== in;
    lt_9.in[1] <== 62;

    component eq_plus = IsEqual();
    eq_plus.in[0] <== in;
    eq_plus.in[1] <== 62;

    component eq_underscore = IsEqual();
    eq_underscore.in[0] <== in;
    eq_underscore.in[1] <== 63;

    signal uppercase <== lt_Z.out * (in+65);
    signal lowercase <== (lt_z.out - lt_Z.out) * (in+71); // in-26+97
    signal number <== (lt_9.out - lt_z.out) * (in-4); //in-52+48
    signal special <== (eq_plus.out * 45) + (eq_underscore.out * 95);

    out <== uppercase + lowercase + number + special;
}
