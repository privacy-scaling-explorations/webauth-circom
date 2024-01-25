//require("hardhat-circom");

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: {
    compilers: [
      {
        version: "0.8.21",
      },
    ],
  },
  // circom: {
  //   inputBasePath: "./circuits",
  //   ptau: "pot23_final.ptau",
  //   circuits: [
  //     {
  //       name: "webauthn_default",
  //       // No protocol, so it defaults to groth16
  //     },
  //     // {
  //     //   name: "simple-polynomial",
  //     //   // Generate PLONK
  //     //   protocol: "plonk",
  //     // },
  //     // {
  //     //   name: "hash",
  //     //   // Explicitly generate groth16
  //     //   protocol: "groth16",
  //     // },
  //   ],
  // },
};
