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
    title: "ETPRO ATTACK_RESPONSE Snake Keylogger Config Inbound",
  }), []);

  assert.deepEqual(ids({
    title: "ET INFO Keylogger Style External IP Check",
  }), []);
});

test("gap signals identify credential dumping sub-techniques only from explicit titles", () => {
  assert.deepEqual(ids({ title: "Mimikatz LSASS credential dump" }), ["T1003.001"]);
  assert.deepEqual(ids({ title: "Microsoft Windows LSASS Remote Memory Corruption CVE" }), []);
  assert.deepEqual(ids({ title: "Possible DCSync activity" }), ["T1003.006"]);
  assert.deepEqual(ids({
    title: "Possible /etc/passwd via HTTP",
    sourceFile: "attack_response.rules",
  }), ["T1003.008"]);
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

test("gap signals identify network-observable internet connection discovery", () => {
  assert.deepEqual(ids({ title: "Malware checking whatismyip service" }), ["T1016.001"]);
});

test("gap signals respect the uncovered technique set", () => {
  assert.deepEqual(ids(
    { title: "Keylogger activity and schtasks.exe Scheduled Task" },
    ["T1053.005"],
  ), ["T1053.005"]);
});

test("gap signals do not infer remote-services techniques from protocol alone", () => {
  assert.deepEqual(ids({
    title: "Generic SMB traffic",
    protocol: "smb",
    classtype: "command-and-control",
  }), []);
});
