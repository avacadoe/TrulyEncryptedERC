import { ethers } from "hardhat";

async function main() {
	console.log("\n=== Transaction 1: submitWithdrawIntent ===\n");

	const tx1 = await ethers.provider.getTransaction(
		"0x91a8965c9274b91f717fb75d10b8efe90840fceecbd1f6ff49c51c257f88fa53",
	);
	const receipt1 = await ethers.provider.getTransactionReceipt(
		"0x91a8965c9274b91f717fb75d10b8efe90840fceecbd1f6ff49c51c257f88fa53",
	);

	console.log("From:", tx1?.from);
	console.log("To:", tx1?.to);
	console.log("Gas Used:", receipt1?.gasUsed.toString());
	console.log("Block Number:", receipt1?.blockNumber);
	console.log("Status:", receipt1?.status === 1 ? "Success" : "Failed");

	const encryptedERC = await ethers.getContractAt(
		"EncryptedERC",
		"0x1E8617263656B945087bC4bEaaB530Af6fD844dD",
	);

	console.log("\nDecoded Events:");
	if (receipt1) {
		for (const log of receipt1.logs) {
			try {
				const parsed = encryptedERC.interface.parseLog({
					topics: log.topics as string[],
					data: log.data,
				});
				if (parsed) {
					console.log(`\n  Event: ${parsed.name}`);
					for (let i = 0; i < parsed.args.length; i++) {
						const argName = parsed.fragment.inputs[i]?.name || `arg${i}`;
						console.log(`    ${argName}:`, parsed.args[i].toString());
					}
				}
			} catch (e) {}
		}
	}

	console.log("\n\n=== Transaction 2: executeWithdrawIntent ===\n");

	const tx2 = await ethers.provider.getTransaction(
		"0xafe40736bacc330600cb138662a775c5aaea2c976c2046a9946ae1d7b894b77d",
	);
	const receipt2 = await ethers.provider.getTransactionReceipt(
		"0xafe40736bacc330600cb138662a775c5aaea2c976c2046a9946ae1d7b894b77d",
	);

	console.log("From:", tx2?.from);
	console.log("To:", tx2?.to);
	console.log("Gas Used:", receipt2?.gasUsed.toString());
	console.log("Block Number:", receipt2?.blockNumber);
	console.log("Status:", receipt2?.status === 1 ? "Success" : "Failed");

	const erc20 = await ethers.getContractAt(
		"SimpleERC20",
		"0xA4DeF71A5848768e4E33256aFfc2E83733DE424a",
	);

	console.log("\nDecoded Events:");
	if (receipt2) {
		for (const log of receipt2.logs) {
			try {
				const parsed = encryptedERC.interface.parseLog({
					topics: log.topics as string[],
					data: log.data,
				});
				if (parsed) {
					console.log(`\n  Event: ${parsed.name}`);
					for (let i = 0; i < parsed.args.length; i++) {
						const argName = parsed.fragment.inputs[i]?.name || `arg${i}`;
						let value = parsed.args[i];

						// Format addresses and large numbers nicely
						if (argName.includes("address") || argName === "from" || argName === "to" || argName === "user" || argName === "executor") {
							value = value.toString();
						} else if (argName === "amount") {
							// This is in scaled units (2 decimals)
							value = `${value.toString()} (scaled units)`;
						} else if (typeof value === "bigint") {
							value = value.toString();
						}

						console.log(`    ${argName}:`, value);
					}
				}
			} catch (e) {
				// Try ERC20 interface for Transfer events
				try {
					const parsedERC20 = erc20.interface.parseLog({
						topics: log.topics as string[],
						data: log.data,
					});
					if (parsedERC20) {
						console.log(`\n  Event: ${parsedERC20.name} (ERC20)`);
						for (let i = 0; i < parsedERC20.args.length; i++) {
							const argName = parsedERC20.fragment.inputs[i]?.name || `arg${i}`;
							let value = parsedERC20.args[i];

							if (argName === "value") {
								// This is in ERC20 decimals (18)
								value = `${ethers.formatUnits(value, 18)} TEST tokens`;
							} else {
								value = value.toString();
							}

							console.log(`    ${argName}:`, value);
						}
					}
				} catch (e2) {}
			}
		}
	}

	// Now let's get the actual intent details
	console.log("\n\n=== Intent Details ===\n");
	const intentHash = "0x130092fabd6c6687fcb83de3a24fbdfbba8b42e85cbc72b987e9bd908d41d6ee";
	const intent = await encryptedERC.withdrawIntents(intentHash);

	console.log("Intent Hash:", intentHash);
	console.log("User:", intent.user);
	console.log("Token ID:", intent.tokenId.toString());
	console.log("Submitted At:", new Date(Number(intent.timestamp) * 1000).toISOString());
	console.log("Executed:", intent.executed);
	console.log("Cancelled:", intent.cancelled);

	// Get time difference
	const submitBlock = await ethers.provider.getBlock(receipt1?.blockNumber!);
	const executeBlock = await ethers.provider.getBlock(receipt2?.blockNumber!);
	const timeDiff = Number(executeBlock?.timestamp) - Number(submitBlock?.timestamp);

	console.log("\n=== Timing Analysis ===\n");
	console.log("Submit Block:", receipt1?.blockNumber, `at ${new Date(Number(submitBlock?.timestamp) * 1000).toISOString()}`);
	console.log("Execute Block:", receipt2?.blockNumber, `at ${new Date(Number(executeBlock?.timestamp) * 1000).toISOString()}`);
	console.log("Time Difference:", `${timeDiff} seconds`);
	console.log(
		"USER_ONLY_DELAY (1 hour):",
		timeDiff < 3600 ? "✓ Within user-only window" : "✗ Outside user-only window",
	);
	console.log(
		"PERMISSIONLESS_DELAY (24 hours):",
		timeDiff < 86400 ? "Still restricted" : "Permissionless execution allowed",
	);
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
