# Webauthn Circom Verifier
This project provides a circuit that verifies the ECDSA signature of a p256 [webauthn](https://www.w3.org/TR/webauthn/) credential. The purpose of webauthn is to provide authentication to services using passwordless methods involving signing with a cryptographic key. 

Given the wide-spread deployment of the NIST P-256 curve due to its standardization and [reccomendation](https://csrc.nist.gov/pubs/sp/800/186/final), a majority of modern devices contain some form of secure element that can perform P-256 signatures with a private key that does not leave the secure hardware.

This circuit depends on the [circom-ecdsa-p256](https://github.com/privacy-scaling-explorations/circom-ecdsa-p256) circuit for the signature verification.

## Motivation
Ethereum ECDSA signatures with normal EOA accounts can only utilize the [secp256k1](https://neuromancer.sk/std/secg/secp256k1), which has seen little adoption outside of cryptocurrency related projects. With the introduction and continued development of [account abstraction](https://ethereum.org/en/roadmap/account-abstraction) standards within Ethereum, alternative authentication flows are enabled for users.

Given the webauthn standard, which has an option to use P-256, is becoming more pervasive it is a natural fit for pairing with account abstraction to provide an improved UX compared to the normal EOA flow.

Utilizing succinct proofs enables us to verify the legitimacy of a [webauthn assertion](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion) against a public key without providing that data to the function.

In order to approve transactions, we simply calculate the challenge as:
```
hash = sha256(target || calldata || nonce)
challenge = hash[1:32]
```

We truncate the hash to 31 bytes as this ensures the challenge fits inside of the default field of circom.

## Circuit Verification
The circuit verifies the following:
- This is a `webauthn.get` response
- The challenge is correctly incorporated inside of the `authDataJSON`
- Calculate the message hash in the context of ECDSA in the circuit
- The signature on the message hash is valid

The file `scripts/compute_json_variables.py` will generate hardcoded byte values of the JSON format of the `authDataJSON` structure. These hardcodes are used to verify the proper formation of this structure and the included challenge.

The two **public** inputs of the circuit are the public key of the signer, and the challenge.

After we have proven the correct webauthn assertion of the public key signing the challenge, the proof data and public inputs are send to the `TransactionApprover`. This smart contract will verify the correctness of the zk proof, and additionally calculate the challenge data to ensure that it is correctly formed from the requested transaction.

After that verification, the requested transaction is executed.

## Install
- Run `git pull --recurse-submodules`
- Run `git submodule update --init --recursive` to grab the ECDSA dependencies
- Run `yarn` to install dependencies

### Compiling
After all the dependencies have been sync'd, you run `generate_verifier.sh` inside of the `scripts/` folder. This will compile the circuit, generate test keys and generate the solidity verifier inside of `contracts/`.

### Benchmarks
All benchmarks were run on an AMD 7700x, 32GB RAM desktop. The `max_auth_data_bytes` is 64 and `max_client_data_bytes` is 256.

| Constraints | 2811775 |
| Circuit compilation | 71s |
| Trusted setup phase 2 key generation | 565s |
| Trusted setup phase 2 contribution | 138s |
| Proving key size | 1.7G |
| Witness generation | 78s |
| Proving time | 42s |
| Proof verification time | 1s |

## Testing
Given that webauthn's focus is for browser-based authentication, the tests rely on hardcoded test data with assertions generated from a [virtual authenticator](https://gramthanos.github.io/WebDevAuthn/credential-get.html).

The `TransactionApprover` test will call the previously compiled circuit with the test data, and then pass that proof along to the smart contract to verify a test ERC20 transfer.