import { ethers } from "hardhat";
import { deployLibrary, deployVerifiers } from "../test/helpers";
import { EncryptedERC__factory } from "../typechain-types";
import { DECIMALS } from "./constants";

// Auditor BabyJubJub public key
const AUDITOR_PUBLIC_KEY: [bigint, bigint] = [
    13441078791254289223338373448867820513144420894110953117289287637725783385214n,
    4516648389695980764767481409510315167649898417254172432444019091640702755942n,
];

// Denominations in TEST units (18 decimals): 100, 500, 1000, 5000, 10000
const DENOMINATIONS = [
    ethers.parseEther("100"),
    ethers.parseEther("500"),
    ethers.parseEther("1000"),
    ethers.parseEther("5000"),
    ethers.parseEther("10000"),
];

// Batch windows: 1d, 1w, 2w, 4w, 8w (in seconds)
const BATCH_WINDOWS = [
    86400n,     // 1 day
    604800n,    // 1 week
    1209600n,   // 2 weeks
    2419200n,   // 4 weeks
    4838400n,   // 8 weeks
];

const main = async () => {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying with:", deployer.address);

    // Deploy verifiers
    const {
        registrationVerifier,
        mintVerifier,
        withdrawVerifier,
        withdrawIntentVerifier,
        transferVerifier,
        burnVerifier,
    } = await deployVerifiers(deployer);

    // Deploy BabyJubJub library
    const babyJubJub = await deployLibrary(deployer);

    // Deploy Registrar
    const registrarFactory = await ethers.getContractFactory("Registrar");
    const registrar = await registrarFactory.deploy(registrationVerifier);
    await registrar.waitForDeployment();

    // Deploy EncryptedERC (converter mode)
    const encryptedERCFactory = new EncryptedERC__factory({
        "contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub,
    });
    const encryptedERC = await encryptedERCFactory.connect(deployer).deploy({
        registrar: registrar.target,
        isConverter: true,
        name: "",
        symbol: "",
        mintVerifier,
        withdrawVerifier,
        withdrawIntentVerifier,
        transferVerifier,
        burnVerifier,
        decimals: DECIMALS,
    });
    await encryptedERC.waitForDeployment();

    // Deploy TEST token
    const erc20Factory = await ethers.getContractFactory("SimpleERC20");
    const erc20 = await erc20Factory.deploy("Test", "TEST", 18);
    await erc20.waitForDeployment();

    // Mint TEST tokens to deployer
    const mintTx = await erc20.mint(deployer.address, ethers.parseEther("100000"));
    await mintTx.wait();
    console.log("Minted 100000 TEST to deployer");

    // Set auditor public key
    const setAuditorTx = await encryptedERC.setAuditorPublicKey(AUDITOR_PUBLIC_KEY);
    await setAuditorTx.wait();
    console.log("Auditor public key set:", AUDITOR_PUBLIC_KEY.map(v => v.toString()));

    // Set batch windows
    const setBatchWindowsTx = await encryptedERC.setBatchWindows(BATCH_WINDOWS);
    await setBatchWindowsTx.wait();
    console.log("Batch windows set:", BATCH_WINDOWS.map(w => w.toString()).join(", "), "seconds");

    // Approve and deposit a small amount to auto-register the TEST tokenId
    const approvalTx = await erc20.approve(encryptedERC.target, ethers.parseEther("100000"));
    await approvalTx.wait();
    console.log("Approved EncryptedERC to spend TEST");

    // Note: actual deposit requires a ZK proof, so we use addToken helper if available,
    // or the deployer must do a first deposit via the UI / test script.
    // For now, just log the token address — setDenominations must be called after first deposit registers the tokenId.
    console.log("\n*** ACTION REQUIRED ***");
    console.log("After first deposit of TEST into the contract (auto-registers tokenId),");
    console.log("run this to set denominations:");
    console.log(`  const tokenId = await encryptedERC.tokenIds("${erc20.target}");`);
    console.log(`  await encryptedERC.setDenominations(tokenId, [${DENOMINATIONS.map(d => `"${d.toString()}"`).join(", ")}]);`);
    console.log("**********************\n");

    console.table({
        registrationVerifier,
        mintVerifier,
        withdrawVerifier,
        withdrawIntentVerifier,
        transferVerifier,
        burnVerifier,
        babyJubJub,
        registrar: registrar.target,
        encryptedERC: encryptedERC.target,
        erc20: erc20.target,
    });

    console.log("\nUpdate avacado_front/src/config/contracts.ts with:");
    console.log(`  EERC_CONVERTER: "${encryptedERC.target}"`);
    console.log(`  ERC20: "${erc20.target}"`);
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
