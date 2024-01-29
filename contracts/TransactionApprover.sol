pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/Address.sol";
import "./webauthn_verifier.sol";

import "hardhat/console.sol";

contract TransactionApprover is Groth16Verifier {
  struct Account {
    uint256[2] pubkey;
    uint256 nonce;
  }

  // Map of x-coordinate to the account
  mapping(uint256 => Account) accounts;

  function pubkeyToRegisters(uint256[2] memory pubkey) public pure returns (uint256[6][2] memory registers) {
    uint256 x = pubkey[0];
    uint256 y = pubkey[1];

    for (uint i = 0; i < 6; i++) {
      registers[0][i] = x & 0x7ffffffffff;
      registers[1][i] = y & 0x7ffffffffff;
      x >>= 43;
      y >>= 43;
    }

    return registers;
  }

  function register(uint256[2] memory pubkey) external {
    Account storage account = accounts[pubkey[0]];
    if (account.pubkey[0] == 0) {
      account.pubkey = pubkey;
    }
  }

  struct ProofArgs {
    uint256[13] pubSignals; // [x, y, challenge]

    uint[2] _pA;
    uint[2][2]  _pB;
    uint[2]  _pC;
  }

  /// In future implementations, one can include the sender as a parameter as an authorizer could approve
  /// transactions for different addresses depending on some form of access control
  /// @param signer The x-coordinate of the account sending the transaction
  function execute(
    uint256 signer,
    address target,
    bytes calldata data,
    uint256 nonce,
    ProofArgs calldata args
  ) external returns (bool) {
    //bytes memory signer_bytes = new bytes(32);
    bytes memory target_bytes = new bytes(32);
    bytes memory nonce_bytes = new bytes(32);
    assembly {
      //mstore(add(signer_bytes, 32), signer)
      mstore(add(target_bytes, 32), target)
      mstore(add(nonce_bytes, 32), nonce)
    }
    bytes memory preimage = bytes.concat(target_bytes, data, nonce_bytes);

    bytes32 hash = sha256(preimage);

    // The challenge is the lowest 248 bits
    uint256 challenge = uint256(hash) & (2**248-1);
    require(challenge == args.pubSignals[12], "Challenges dont match");

    uint256[2] memory pubkey = accounts[signer].pubkey;
    if (pubkey[0] == 0) {
      return false;
    }

    uint[6][2] memory registers = pubkeyToRegisters(pubkey);
    for (uint i = 0; i < 2; i++) {
      for (uint j = 0; j < 6; j++) {
        if (registers[i][j] != args.pubSignals[i*6+j]) {
          return false;
        }
      }
    }
    require(this.verifyProof(args._pA, args._pB, args._pC, args.pubSignals), "Proof failed");
    
    (bool res) = abi.decode(Address.functionCall(target, data), (bool));
    return res;
  }
}