const assert = require("node:assert/strict");
const test = require("node:test");

const { findGapSignals } = require("../src/services/mitreGapSignals");

function ids(rule, uncovered = null) {
  return findGapSignals(rule, uncovered ? new Set(uncovered) : null)
    .map((item) => item.techniqueId);
}

test("gap signals identify explicit keylogging semantics", () => {
  assert.deepEqual(ids({
    title: "ET MALWARE SC-KeyLog Keylogger Installed - Sending Initial Email Report",
  }), ["T1056.001"]);
});

test("gap signals identify credential dumping sub-techniques only from explicit titles", () => {
  assert.deepEqual(ids({ title: "Mimikatz LSASS credential dump" }), ["T1003.001"]);
  assert.deepEqual(ids({ title: "Possible DCSync activity" }), ["T1003.006"]);
  assert.deepEqual(ids({ title: "Attempt to read /etc/shadow" }), ["T1003.008"]);
});

test("gap signals identify scheduled task and WMI execution semantics", () => {
  assert.deepEqual(ids({ title: "Remote WMIC process execution" }), ["T1047"]);
  assert.deepEqual(ids({ title: "schtasks.exe Scheduled Task creation" }), ["T1053.005"]);
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
