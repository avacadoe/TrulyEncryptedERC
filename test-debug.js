const { ethers } = require("hardhat");

async function main() {
  const [signer] = await ethers.getSigners();
  console.log("Signer:", signer.address);
}

main().catch(console.error);
