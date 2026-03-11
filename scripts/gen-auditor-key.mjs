import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { randomBytes } from "node:crypto";

// Generate random 32-byte private key scalar
const rawBytes = randomBytes(32);
const privKey = BigInt("0x" + rawBytes.toString("hex")) % 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const pubKey = mulPointEscalar(Base8, privKey);

console.log("AUDITOR_PRIVATE_KEY=" + privKey.toString());
console.log("AUDITOR_PUBLIC_KEY_X=" + pubKey[0].toString());
console.log("AUDITOR_PUBLIC_KEY_Y=" + pubKey[1].toString());
