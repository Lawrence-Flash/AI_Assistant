import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { parseInventoryCsv, matchInventory, cmpVersion } = require("../site/js/match.js");

const catalog = [
  {
    cve_id: "CVE-EXCHANGE",
    kind: "cve",
    vendor: "Microsoft",
    product: "Exchange Server",
    score: 90,
    version_ranges: [],
    aliases: [{ vendor: "microsoft", product: "exchange_server" }],
    what_to_do: "Patch Exchange.",
    summary: "Exchange is affected.",
    reasons: ["KEV"]
  },
  {
    cve_id: "CVE-IKE",
    kind: "cve",
    vendor: "Microsoft",
    product: "Internet Key Exchange (IKE) Service Extensions",
    score: 88,
    version_ranges: [],
    aliases: [],
    what_to_do: "Not mail.",
    summary: "IKE.",
    reasons: []
  },
  {
    cve_id: "CVE-FORTI",
    kind: "cve",
    vendor: "Fortinet",
    product: "FortiOS",
    score: 70,
    version_ranges: [
      {
        vendor: "fortinet",
        product: "fortios",
        version: "*",
        start_including: "7.2.0",
        start_excluding: null,
        end_including: null,
        end_excluding: "7.2.5"
      }
    ],
    aliases: [],
    what_to_do: "Patch FortiOS.",
    summary: "FortiOS.",
    reasons: []
  },
  {
    cve_id: "CVE-WP",
    kind: "cve",
    vendor: "WordPress",
    product: "Core",
    score: 40,
    version_ranges: [
      {
        vendor: "wordpress",
        product: "wordpress",
        version: "6.4.2",
        start_including: null,
        start_excluding: null,
        end_including: null,
        end_excluding: null
      }
    ],
    aliases: [{ vendor: "wordpress", product: "wordpress" }],
    what_to_do: "Update WordPress.",
    summary: "WordPress core.",
    reasons: []
  },
  {
    cve_id: "CVE-WIN",
    kind: "cve",
    vendor: "Microsoft",
    product: "Windows",
    score: 55,
    version_ranges: [],
    aliases: [],
    what_to_do: "Patch Windows.",
    summary: "Windows.",
    reasons: []
  },
  {
    cve_id: "CVE-TPLINK",
    kind: "cve",
    vendor: "TP-Link",
    product: "TL-WR841N",
    score: 30,
    version_ranges: [],
    aliases: [],
    what_to_do: "Replace or patch the router.",
    summary: "Old router.",
    reasons: []
  }
];

assert.equal(cmpVersion("7.2.4", "7.2.5"), -1);
assert.equal(cmpVersion("7.2.10", "7.2.9"), 1);
assert.equal(cmpVersion("1.0", "1.0.0"), 0);
assert.equal(cmpVersion("22H2", "22h2"), 0);

const quoted = parseInventoryCsv('\ufeffproduct,manufacturer,ver\n"Exchange Server","Microsoft","15.2.1000"\n');
assert.equal(quoted[0].name, "Exchange Server");
assert.equal(quoted[0].vendor, "Microsoft");
assert.equal(quoted[0].version, "15.2.1000");
assert.throws(() => parseInventoryCsv("version,notes\n1.0,hello\n"), /name/);

const rows = parseInventoryCsv(
  [
    "name,vendor,version",
    "Exchange Server,Microsoft,2019",
    "FortiOS,Fortinet,7.2.4",
    "FortiOS,Fortinet,7.2.5",
    "WordPress,WordPress,6.4.2",
    "WordPress,WordPress,6.5.0",
    "Windows 10,Microsoft,",
    "Office printer,Generic,1.0",
    "Yoco Neo,Yoco,1.0",
    "TL-WR841N,TP-Link,"
  ].join("\n")
);
const result = matchInventory(rows, catalog);
const affected = result.affected.map((item) => [item.inventory.name, item.inventory.version, item.cve_id, item.confidence]);
assert.deepEqual(affected, [
  ["Exchange Server", "2019", "CVE-EXCHANGE", "name_only"],
  ["FortiOS", "7.2.4", "CVE-FORTI", "version_in_range"],
  ["Windows 10", "", "CVE-WIN", "name_only"],
  ["WordPress", "6.4.2", "CVE-WP", "version_exact"],
  ["TL-WR841N", "", "CVE-TPLINK", "name_only"]
]);
assert.deepEqual(result.affected.map((item) => item.score), [90, 70, 55, 40, 30]);
const cleared = new Set(result.cleared.map((item) => item.inventory.version + "|" + item.cve_id));
assert.equal(cleared.has("7.2.5|CVE-FORTI"), true);
assert.equal(cleared.has("6.5.0|CVE-WP"), true);
const ids = new Set([...result.affected, ...result.cleared].map((item) => item.cve_id));
assert.equal(ids.has("CVE-IKE"), false);
assert.equal(result.affected.some((item) => item.inventory.name === "Office printer"), false);
assert.equal(result.affected.some((item) => item.inventory.name === "Yoco Neo"), false);
assert.match(result.affected[0].confidence_label, /approximate/i);

const tied = matchInventory(
  parseInventoryCsv("name,vendor,version\nWindows,Microsoft,\n"),
  [
    { ...catalog[4], cve_id: "CVE-OLD", score: 40, kev_date_added: "2008-01-01" },
    { ...catalog[4], cve_id: "CVE-NEW", score: 40, kev_date_added: "2026-10-13" }
  ]
);
assert.deepEqual(tied.affected.map((item) => item.cve_id), ["CVE-NEW", "CVE-OLD"]);

const genericCatalog = catalog.concat([
  { cve_id: "CVE-APACHE", kind: "cve", vendor: "Apache", product: "HTTP Server", score: 25, version_ranges: [], aliases: [], what_to_do: "Patch Apache.", summary: "Apache.", reasons: [] },
  { cve_id: "CVE-TRUECONF", kind: "cve", vendor: "TrueConf", product: "Server", score: 25, version_ranges: [], aliases: [], what_to_do: "Patch TrueConf.", summary: "TrueConf.", reasons: [] }
]);
const generic = matchInventory(parseInventoryCsv("name,vendor,version\nHP HTTP Server,,\nApache HTTP Server,Apache,\n"), genericCatalog);
assert.equal(generic.affected.some((item) => item.inventory.name === "HP HTTP Server"), false);
assert.equal(generic.affected.some((item) => item.inventory.name === "Apache HTTP Server" && item.cve_id === "CVE-APACHE"), true);
assert.equal(generic.affected.some((item) => item.cve_id === "CVE-TRUECONF"), false);

console.log("match.js tests passed");
