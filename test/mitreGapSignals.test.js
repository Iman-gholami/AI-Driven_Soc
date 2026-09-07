const assert = require("node:assert/strict");
const test = require("node:test");

const { findGapSignals } = require("../src/services/mitreGapSignals");

function ids(rule, uncovered = null) {
  return findGapSignals(rule, uncovered ? new Set(uncovered) : null)
    .map((item) => item.techniqueId);
}

test("gap signals identify behavioral keylogging semantics", () => {
  assert.deepEqual(ids({
    title: "ET MALWARE PerfectKeylogger Storing Keystrokes Via FTP",
  }), ["T1056.001"]);

  assert.deepEqual(ids({
    title: "ET MALWARE HawkEye Keylogger Report SMTP",
  }), ["T1056.001"]);

  assert.deepEqual(ids({
    title: "ET MALWARE Generic Keylogger SMTP",
  }), []);

  assert.deepEqual(ids({
    title: "ETPRO ATTACK_RESPONSE Snake Keylogger Config Inbound",
  }), []);

  assert.deepEqual(ids({
    title: "ET INFO Keylogger Style External IP Check",
  }), []);
});

test("gap signals identify credential dumping sub-techniques only from explicit behavior", () => {
  assert.deepEqual(ids({ title: "Mimikatz LSASS credential dump" }), ["T1003.001"]);
  assert.deepEqual(ids({ title: "Microsoft Windows LSASS Remote Memory Corruption CVE" }), []);
  assert.deepEqual(ids({ title: "Possible DCSync activity" }), ["T1003.006"]);
  assert.deepEqual(ids({ title: "Dump SAM Script Retrieval" }), []);
  assert.deepEqual(ids({
    title: "Possible /etc/passwd via HTTP",
    sourceFile: "attack_response.rules",
  }), []);
  assert.deepEqual(ids({
    title: "/etc/shadow Detected in URI",
    sourceFile: "web_server.rules",
  }), []);
});

test("gap signals identify scheduled task and WMI execution semantics", () => {
  assert.deepEqual(ids({ title: "Remote WMI execution" }), ["T1047"]);
  assert.deepEqual(ids({ title: "WMIC OS get Microsoft Windows DOS prompt command exit" }), []);
  assert.deepEqual(ids({ title: "schtasks.exe /create suspicious task" }), ["T1053.005"]);
  assert.deepEqual(ids({ title: "Windows Scheduled Task XML Response from Server" }), []);
});

test("gap signals identify exact process injection variants", () => {
  assert.deepEqual(ids({ title: "Malware DLL Injection attempt" }), ["T1055.001"]);
  assert.deepEqual(ids({ title: "Observed Process Doppelganging behavior" }), ["T1055.013"]);
});

test("gap signals do not infer internet connection discovery from generic IP-check traffic", () => {
  assert.deepEqual(ids({ title: "Malware checking whatismyip service" }), []);
  assert.deepEqual(ids({ title: "ET POLICY Possible IP Check api.ipify.org" }), []);
});

test("gap signals respect the uncovered technique set", () => {
  assert.deepEqual(ids(
    { title: "Keylogger reporting activity and schtasks.exe /create suspicious task" },
    ["T1053.005"],
  ), ["T1053.005"]);
});

test("gap signals do not infer scheduled task creation from a generic mention", () => {
  assert.deepEqual(ids({
    title: "Windows Scheduled Task XML Response from Server",
  }), []);
});

test("gap signals do not infer remote-services techniques from protocol alone", () => {
  assert.deepEqual(ids({
    title: "Generic SMB traffic",
    protocol: "smb",
    classtype: "command-and-control",
  }), []);
});
