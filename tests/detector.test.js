const { detectMultisigAnomalies } = require("../src/detector");

describe("MultisigAnomalyDetector", () => {
  it("should trigger for unauthorized signer", async () => {
    const txEvent = {
      from: "0xBADF00D123...",
      to: "0xMultisigContract...",
      block: { timestamp: 100000 },
      transaction: { data: "0x6a627842..." }
    };

    const findings = await detectMultisigAnomalies(txEvent);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].id).toBe("MULTISIG-1");
  });

  it("should detect rapid consecutive signatures", async () => {
    const txEvent1 = {
      from: "0xTrustedSigner1",
      to: "0xMultisigContract...",
      block: { timestamp: 100000 },
      transaction: { data: "0x6a627842..." }
    };

    const txEvent2 = {
      from: "0xTrustedSigner1",
      to: "0xMultisigContract...",
      block: { timestamp: 100002 },
      transaction: { data: "0x6a627842..." }
    };

    await detectMultisigAnomalies(txEvent1);
    const findings = await detectMultisigAnomalies(txEvent2);
    expect(findings.some(f => f.id === "MULTISIG-3")).toBeTruthy();
  });
});
