import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { parseNmapXml, parseWithRegex, inventoryRows, parseCpe } = require("../site/js/nmap.js");

const xml = fs.readFileSync(new URL("../site/sample-nmap.xml", import.meta.url), "utf8");
const report = parseWithRegex(xml);
const rows = inventoryRows(report);

function at(host, port) {
  const found = rows.find((row) => row.host === host && row.port === String(port));
  assert.ok(found, host + ":" + port);
  return found;
}

assert.equal(report.hosts.length, 10);
assert.equal(at("192.168.1.10", 445).name, "Windows 10");
assert.equal(at("192.168.1.10", 445).vendor, "Microsoft");
assert.equal(at("192.168.1.10", 445).source, "cpe");
assert.equal(at("192.168.1.30", 443).name, "Exchange Server");
assert.equal(at("192.168.1.30", 443).version, "2019");
assert.equal(at("192.168.1.35", 80).name, "WordPress");
assert.equal(at("192.168.1.35", 80).version, "6.4.2");
assert.equal(at("192.168.1.40", 443).name, "FortiOS");
assert.equal(at("192.168.1.40", 443).vendor, "Fortinet");
assert.equal(at("192.168.1.40", 443).version, "7.2.4");
assert.equal(at("192.168.1.20", 8291).name, "RouterOS");
assert.equal(at("192.168.1.20", 8291).vendor, "MikroTik");
assert.equal(at("192.168.1.20", 22).version, "7.2p2");
assert.equal(at("192.168.1.40", 22).version, "9.6p1");
assert.equal(at("192.168.1.50", 3306).name, "MySQL");
assert.equal(at("192.168.1.50", 3306).vendor, "Oracle");
assert.equal(at("192.168.1.50", 3306).version, "5.7.33");
assert.equal(at("192.168.1.70", 80).name, "TL-WR841N");
assert.equal(at("192.168.1.70", 80).vendor, "TP-Link");
assert.equal(at("192.168.1.70", 80).source, "banner");
assert.equal(at("192.168.1.60", 9100).name, "HP LaserJet 400");
assert.equal(at("192.168.1.60", 9200).name, "HP HTTP Server");
assert.equal(rows.some((row) => row.host === "192.168.1.99"), false);
assert.equal(rows.some((row) => row.host === "192.168.1.10" && row.port === "135"), false);
assert.equal(rows.some((row) => row.host === "192.168.1.10" && row.port === "3389"), false);
assert.equal(rows.some((row) => row.port === "23"), false);

const cpe = parseCpe("cpe:2.3:a:oracle:mysql:5.7.33:*:*:*:*:*:*:*");
assert.equal(cpe.product, "MySQL");
assert.equal(cpe.vendor, "Oracle");
assert.equal(cpe.version, "5.7.33");

assert.throws(() => parseNmapXml("<html></html>"), /nmap/);
assert.equal(parseNmapXml(xml).hosts.length, report.hosts.length);

console.log("nmap xml tests passed (" + rows.length + " inventory rows)");
