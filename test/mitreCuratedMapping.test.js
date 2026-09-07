const assert = require("node:assert/strict");
const test = require("node:test");

const { deriveCuratedMitreMappings } = require("../src/services/mitreCuratedMapping");

function techniqueIds(rule) {
  return deriveCuratedMitreMappings(rule).techniqueIds;
}

test("curated mapping maps phishing family to parent Phishing technique", () => {
  assert.deepEqual(techniqueIds({
    sourceFile: "phishing.rules",
    classtype: "social-engineering",
    protocol: "http",
    title: "ET PHISHING Chase Account Phish Landing",
    parsedRule: {},
  }), ["T1566"]);
});

test("curated mapping maps DNS and HTTP C2 to protocol sub-techniques", () => {
  assert.deepEqual(techniqueIds({
    sourceFile: "malware.rules",
    classtype: "command-and-control",
    protocol: "dns",
    title: "C2 DNS checkin",
    parsedRule: {},
  }), ["T1071.004"]);

  assert.deepEqual(techniqueIds({
    sourceFile: "mobile_malware.rules",
    classtype: "command-and-control",
    protocol: "http",
    title: "CnC Server Acknowledgement",
    parsedRule: {},
  }), ["T1071.001"]);
});

test("curated mapping recognizes explicit process hollowing semantics", () => {
  assert.deepEqual(techniqueIds({
    sourceFile: "hunting.rules",
    classtype: "bad-unknown",
    protocol: "http",
    title: "Possible Malware Process Hollowing via ZwUnmapViewOfSection",
    parsedRule: {},
  }), ["T1055.012"]);
});

test("curated mapping recognizes conservative obfuscation indicators", () => {
  assert.deepEqual(techniqueIds({
    sourceFile: "hunting.rules",
    classtype: "misc-activity",
    protocol: "http",
    title: "Suspicious CollectGarbage in base64",
    parsedRule: {},
  }), ["T1027"]);

  assert.deepEqual(techniqueIds({
    sourceFile: "web_client.rules",
    classtype: "bad-unknown",
    protocol: "tcp",
    title: "Hex Obfuscation of String.fromCharCode % Encoding",
    parsedRule: {},
  }), ["T1027"]);
});

test("curated mapping maps client endpoint vulnerability exploits to T1203", () => {
  assert.deepEqual(techniqueIds({
    sourceFile: "web_client.rules",
    classtype: "attempted-user",
    protocol: "tcp",
    title: "RealPlayer FLV Parsing Integer Overflow Attempt",
    parsedRule: {
      references: ["cve,2010-3000"],
      metadata: "attack_target Client_Endpoint, cve CVE_2010_3000, tag Web_Client_Attacks",
    },
  }), ["T1203"]);
});

test("curated mapping does not map generic exploit rules without client-target evidence", () => {
  assert.deepEqual(techniqueIds({
    sourceFile: "exploit.rules",
    classtype: "suspicious-login",
    protocol: "tcp",
    title: "Pwdump3e Session Established Reg-Entry port 139",
    parsedRule: {},
  }), []);
});

test("curated mapping does not map generic exploit-kit URL/download detections", () => {
  assert.deepEqual(techniqueIds({
    sourceFile: "exploit_kit.rules",
    classtype: "exploit-kit",
    protocol: "http",
    title: "Likely Scalaxy Exploit Kit URL template download",
    parsedRule: {},
  }), []);
});

test("curated mapping maps attempted recon scan rules to network service discovery", () => {
  assert.deepEqual(techniqueIds({
    sourceFile: "scan.rules",
    classtype: "attempted-recon",
    protocol: "tcp",
    title: "Possible service scan",
    parsedRule: {},
  }), ["T1046"]);
});
