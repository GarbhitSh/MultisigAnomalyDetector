const signerTimestamps = {};

function isSensitiveCall(sig) {
  const SENSITIVE_METHOD_IDS = [
    "0x3659cfe6", // upgradeTo
    "0x6a627842", // execTransaction
    "0x9e281a98", // addSigner
  ];
  return SENSITIVE_METHOD_IDS.includes(sig);
}

async function isRapidSignature(signer, timestamp, txEvent) {
  const last = signerTimestamps[signer] || 0;
  signerTimestamps[signer] = timestamp;
  return (timestamp - last) < (process.env.MIN_SIGNATURE_INTERVAL_SEC || 5);
}

function isUnauthorizedSigner(signer, allowedSigners) {
  return !allowedSigners.includes(signer.toLowerCase());
}

module.exports = {
  isRapidSignature,
  isSensitiveCall,
  isUnauthorizedSigner,
};
