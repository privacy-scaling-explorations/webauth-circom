import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      {
        version: "0.8.21",
      },
    ],
  },
  typechain: {
    outDir: "./types"
  },
  mocha: {
    timeout: 10000000
  },
}

export default config;
