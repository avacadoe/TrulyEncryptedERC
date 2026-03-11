import { ethers, upgrades } from "hardhat";
import { deployLibrary, deployVerifiers } from "../test/helpers";
import { EncryptedERC, EncryptedERC__factory } from "../typechain-types";
import { DECIMALS } from "./constants";

// Auditor BabyJubJub public key (from keys.md)
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
    86400n,
    604800n,
    1209600n,
    2419200n,
    4838400n,
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
    console.log("Registrar:", registrar.target);

    // Build the factory with linked library
    const encryptedERCFactory = new EncryptedERC__factory(
        { "contracts/libraries/BabyJubJub.sol:BabyJubJub": babyJubJub },
        deployer
    );

    // Deploy UUPS proxy
    const proxy = await upgrades.deployProxy(
        encryptedERCFactory,
        [{
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
        }],
        {
            kind: "uups",
            initializer: "initialize",
            unsafeAllow: ["external-library-linking"],
        }
    );
    await proxy.waitForDeployment();
    const proxyAddress = await proxy.getAddress();
    console.log("EncryptedERC proxy:", proxyAddress);

    // Attach typed interface to proxy
    const encryptedERC: EncryptedERC = EncryptedERC__factory.connect(proxyAddress, deployer);

    // Deploy TEST token
    const erc20Factory = await ethers.getContractFactory("SimpleERC20");
    const erc20 = await erc20Factory.deploy("Test", "TEST", 18);
    await erc20.waitForDeployment();
    console.log("TEST token:", erc20.target);

    // Mint TEST tokens to deployer
    const mintErc20Tx = await (erc20 as unknown as { mint(to: string, amount: bigint): Promise<{ wait(): Promise<void> }> }).mint(
        deployer.address, ethers.parseEther("100000")
    );
    await mintErc20Tx.wait();
    console.log("Minted 100000 TEST to deployer");

    // Set auditor: deployer address + auditor BabyJubJub key
    await encryptedERC.setAuditorKey(deployer.address, AUDITOR_PUBLIC_KEY).then(tx => tx.wait());
    console.log("Auditor set:", deployer.address);
    console.log("Auditor BabyJubJub key:", AUDITOR_PUBLIC_KEY.map(v => v.toString()));

    // Set batch windows
    await encryptedERC.setBatchWindows(BATCH_WINDOWS).then(tx => tx.wait());
    console.log("Batch windows set:", BATCH_WINDOWS.map(w => w.toString()).join(", "), "seconds");

    console.log("\n*** NOTE ***");
    console.log("After first deposit of TEST, run setDenominations:");
    console.log(`  tokenId = await encryptedERC.tokenIds("${erc20.target}")`);
    console.log(`  await encryptedERC.setDenominations(tokenId, [${DENOMINATIONS.map(d => `"${d}"`).join(", ")}])`);
    console.log("***\n");

    console.table({
        registrationVerifier,
        mintVerifier,
        withdrawVerifier,
        withdrawIntentVerifier,
        transferVerifier,
        burnVerifier,
        babyJubJub,
        registrar: registrar.target,
        encryptedERC: proxyAddress,
        erc20: erc20.target,
    });

    console.log("\nUpdate avacado_front/src/config/contracts.ts with:");
    console.log(`  EERC_CONVERTER: "${proxyAddress}"`);
    console.log(`  ERC20: "${erc20.target}"`);
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
