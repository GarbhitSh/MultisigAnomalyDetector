const { createTrigger, getInputAddress, getTxFunctionSig } = require("venn-custom-detection-utils");
const { isRapidSignature, isUnauthorizedSigner, isSensitiveCall } = require("./helpers");

const ALLOWED_SIGNERS = process.env.ALLOWED_SIGNERS?.split(",") || [];
const MIN_SIGNATURE_INTERVAL_SEC = parseInt(process.env.MIN_SIGNATURE_INTERVAL_SEC) || 5;

async function detectMultisigAnomalies(txEvent) {
  const findings = [];

  const signer = txEvent.from.toLowerCase();
  const recipient = txEvent.to?.toLowerCase() || "";
  const timestamp = txEvent.block.timestamp;
  const functionSig = getTxFunctionSig(txEvent.transaction.data);

  // Check: Unauthorized signer
  if (!ALLOWED_SIGNERS.includes(signer)) {
    findings.push(createTrigger("MULTISIG-1", "Unauthorized signer", { signer }));
  }

  // Check: Rapid signing (coordination)
  if (await isRapidSignature(signer, timestamp, txEvent)) {
    findings.push(createTrigger("MULTISIG-3", "Rapid multisig signature pattern", { signer, timestamp }));
  }

  // Check: Sensitive method call
  if (isSensitiveCall(functionSig)) {
    findings.push(createTrigger("MULTISIG-5", "Sensitive multisig function executed", { functionSig }));
  }

  return findings;
}

module.exports = {
  detectMultisigAnomalies
};
