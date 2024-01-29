include "../circuits/webauthn.circom";

// A webauthn verifier with 6 43-bit registers, 64 bytes max auth data, 256 bytes max client data and a challenge size 31 bytes
component main {public [pubkey, challenge]}= WebAuthnVerify(43, 6, 64, 256, 31);