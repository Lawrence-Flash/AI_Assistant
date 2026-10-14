/* Inventory matching for the "Am I affected?" page.
   Keep this in step with threat-brief/collector/match.py.
   It runs in the browser. The inventory file is not uploaded. */
(function (root, factory) {
  var api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.ThreatMatch = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  var GENERIC_PRODUCTS = { core: true, firmware: true, "http server": true, server: true };
  var GENERIC_PREFIX = "multiple";
  var HEADER_ALIASES = {
    name: "name",
    product: "name",
    software: "name",
    asset: "name",
    application: "name",
    vendor: "vendor",
    publisher: "vendor",
    manufacturer: "vendor",
    supplier: "vendor",
    version: "version",
    ver: "version",
    product_version: "version",
    "product version": "version",
    host: "host",
    ip: "host",
    address: "host",
    port: "port"
  };
  var CONFIDENCE_LABELS = {
    version_in_range: "Version looks inside a published range. This check is approximate.",
    version_exact: "Version matches a published CPE version. This check is approximate.",
    name_only: "The name matches, but the feed has no usable version range. Confirm it yourself. This match is approximate.",
    version_outside: "The version sits outside the published ranges we checked. This can be wrong."
  };

  function normalise(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/_/g, " ")
      .replace(/[^a-z0-9]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function containsPhrase(haystack, phrase, minLength) {
    var needle = normalise(phrase);
    var hay = normalise(haystack);
    var limit = minLength || 3;
    if (needle.length < limit || !hay) return false;
    if (needle === hay) return true;
    return (" " + hay + " ").indexOf(" " + needle + " ") !== -1;
  }

  function versionParts(version) {
    var parts = [];
    var chunks = String(version || "").trim().toLowerCase().split(/[.\-_+/\s]+/);
    chunks.forEach(function (chunk) {
      if (!chunk) return;
      var runs = chunk.match(/\d+|[a-z]+/g) || [];
      runs.forEach(function (run) {
        parts.push(/^\d+$/.test(run) ? parseInt(run, 10) : run);
      });
    });
    return parts;
  }

  function cmpVersion(left, right) {
    var a = versionParts(left);
    var b = versionParts(right);
    var length = Math.max(a.length, b.length);
    for (var index = 0; index < length; index += 1) {
      var aa = index < a.length ? a[index] : 0;
      var bb = index < b.length ? b[index] : 0;
      if (typeof aa !== typeof bb) {
        aa = String(aa);
        bb = String(bb);
      }
      if (aa < bb) return -1;
      if (aa > bb) return 1;
    }
    return 0;
  }

  function versionInBounds(version, range) {
    if (range.start_including && cmpVersion(version, range.start_including) < 0) return false;
    if (range.start_excluding && cmpVersion(version, range.start_excluding) <= 0) return false;
    if (range.end_including && cmpVersion(version, range.end_including) > 0) return false;
    if (range.end_excluding && cmpVersion(version, range.end_excluding) >= 0) return false;
    return true;
  }

  function isGeneric(product) {
    var text = normalise(product);
    return !!GENERIC_PRODUCTS[text] || text.indexOf(GENERIC_PREFIX + " ") === 0;
  }

  function productsCompatible(inventoryName, product) {
    return containsPhrase(inventoryName, product) || containsPhrase(product, inventoryName);
  }

  function vendorInRow(vendor, row) {
    return containsPhrase(row.name || "", vendor) || containsPhrase(row.vendor || "", vendor);
  }

  function vendorsContradict(inventoryVendor, item) {
    if (!normalise(inventoryVendor)) return false;
    var vendors = [item.vendor || ""];
    (item.aliases || []).forEach(function (alias) {
      vendors.push(alias.vendor || "");
    });
    var concrete = vendors.filter(function (vendor) { return normalise(vendor); });
    if (!concrete.length) return false;
    return !concrete.some(function (vendor) {
      return containsPhrase(inventoryVendor, vendor) || containsPhrase(vendor, inventoryVendor);
    });
  }

  function recordMatchesRow(row, item) {
    if (vendorsContradict(row.vendor || "", item)) return false;
    var candidates = [];
    if (normalise(item.product || "")) candidates.push(item.product);
    for (var i = 0; i < candidates.length; i += 1) {
      if (isGeneric(candidates[i])) {
        if (vendorInRow(item.vendor || "", row)) return true;
        continue;
      }
      if (productsCompatible(row.name || "", candidates[i])) return true;
    }
    var aliases = item.aliases || [];
    for (var a = 0; a < aliases.length; a += 1) {
      var alias = aliases[a];
      if (vendorsContradict(row.vendor || "", { vendor: alias.vendor || "", aliases: [] })) continue;
      var product = String(alias.product || "").replace(/_/g, " ");
      var vendor = alias.vendor || item.vendor || "";
      if (isGeneric(product)) {
        if (vendorInRow(vendor, row)) return true;
        continue;
      }
      if (productsCompatible(row.name || "", product)) return true;
    }
    return false;
  }

  function relevantRanges(row, item) {
    var ranges = [];
    (item.version_ranges || []).forEach(function (range) {
      var product = String(range.product || "").replace(/_/g, " ");
      var vendor = range.vendor || "";
      if (vendorsContradict(row.vendor || "", { vendor: vendor, aliases: [] })) return;
      if (isGeneric(product)) {
        if (vendorInRow(vendor, row)) ranges.push(range);
        return;
      }
      if (productsCompatible(row.name || "", product)) ranges.push(range);
    });
    return ranges;
  }

  function rangeOutcome(version, range) {
    var hasBounds = range.start_including || range.start_excluding || range.end_including || range.end_excluding;
    var exact = range.version || "";
    if (hasBounds) return versionInBounds(version, range) ? "in" : "out";
    if (exact && exact !== "*" && exact !== "-") return cmpVersion(version, exact) === 0 ? "exact" : "out";
    return "unknown";
  }

  function confidenceFor(row, item) {
    var version = String(row.version || "").trim();
    var ranges = relevantRanges(row, item);
    if (!version || !ranges.length) return "name_only";
    var outcomes = ranges.map(function (range) { return rangeOutcome(version, range); });
    if (outcomes.indexOf("in") !== -1) return "version_in_range";
    if (outcomes.indexOf("exact") !== -1) return "version_exact";
    if (outcomes.length && outcomes.every(function (outcome) { return outcome === "out"; })) return "version_outside";
    return "name_only";
  }

  function parseCsv(text) {
    var rows = [];
    var row = [];
    var field = "";
    var inQuotes = false;
    var source = String(text || "").replace(/^\uFEFF/, "");
    if (!source.trim()) throw new Error("The inventory CSV is empty.");
    for (var i = 0; i < source.length; i += 1) {
      var char = source[i];
      var next = source[i + 1];
      if (inQuotes) {
        if (char === '"' && next === '"') {
          field += '"';
          i += 1;
        } else if (char === '"') {
          inQuotes = false;
        } else {
          field += char;
        }
        continue;
      }
      if (char === '"') {
        inQuotes = true;
      } else if (char === ",") {
        row.push(field);
        field = "";
      } else if (char === "\n" || char === "\r") {
        if (char === "\r" && next === "\n") i += 1;
        row.push(field);
        field = "";
        if (row.some(function (cell) { return String(cell).trim(); })) rows.push(row);
        row = [];
      } else {
        field += char;
      }
    }
    if (field.length || row.length) {
      row.push(field);
      if (row.some(function (cell) { return String(cell).trim(); })) rows.push(row);
    }
    if (!rows.length) throw new Error("The inventory CSV needs a header row with a name column.");
    return rows;
  }

  function parseInventoryCsv(text) {
    var table = parseCsv(text);
    var headers = table[0];
    var mapping = {};
    headers.forEach(function (header, index) {
      var key = normalise(header);
      if (HEADER_ALIASES[key]) mapping[index] = HEADER_ALIASES[key];
    });
    var fields = Object.keys(mapping).map(function (index) { return mapping[index]; });
    if (fields.indexOf("name") === -1) {
      throw new Error("The inventory CSV needs a column named name, product, or software.");
    }
    var items = [];
    for (var r = 1; r < table.length; r += 1) {
      var item = { name: "", vendor: "", version: "", host: "", port: "", line: r + 1 };
      table[r].forEach(function (cell, index) {
        var field = mapping[index];
        var value = String(cell || "").trim();
        if (field && value && !item[field]) item[field] = value;
      });
      if (!item.name && !item.vendor) continue;
      if (!item.name) throw new Error("Row " + item.line + " is missing a product name.");
      items.push(item);
    }
    if (!items.length) throw new Error("The inventory CSV has headers but no data rows.");
    return items;
  }

  function matchInventory(rows, catalog) {
    var affected = [];
    var cleared = [];
    rows.forEach(function (row) {
      (catalog || []).forEach(function (item) {
        if (item.kind && item.kind !== "cve") return;
        if (!recordMatchesRow(row, item)) return;
        var confidence = confidenceFor(row, item);
        var entry = {
          inventory: {
            name: row.name || "",
            vendor: row.vendor || "",
            version: row.version || "",
            host: row.host || "",
            port: row.port ? String(row.port) : ""
          },
          cve_id: item.cve_id,
          title: item.title || item.cve_id,
          vendor: item.vendor || "",
          product: item.product || "",
          score: item.score || 0,
          kev_date_added: item.kev_date_added || "",
          published: item.published || "",
          in_kev: !!item.in_kev,
          cvss: item.cvss,
          smb_matches: item.smb_matches || [],
          what_to_do: item.what_to_do || "",
          summary: item.summary || "",
          reasons: item.reasons || [],
          confidence: confidence,
          confidence_label: CONFIDENCE_LABELS[confidence] || confidence
        };
        if (confidence === "version_outside") cleared.push(entry);
        else affected.push(entry);
      });
    });
    function olderFirst(entry) {
      var raw = entry.kev_date_added || entry.published || "";
      var digits = raw.replace(/\D/g, "");
      if (!digits) return "9";
      return digits.split("").map(function (char) { return String(9 - Number(char)); }).join("");
    }
    affected.sort(function (a, b) {
      if (b.score !== a.score) return b.score - a.score;
      var ad = olderFirst(a);
      var bd = olderFirst(b);
      if (ad < bd) return -1;
      if (ad > bd) return 1;
      if ((a.cve_id || "") < (b.cve_id || "")) return -1;
      if ((a.cve_id || "") > (b.cve_id || "")) return 1;
      if (a.inventory.name < b.inventory.name) return -1;
      if (a.inventory.name > b.inventory.name) return 1;
      return 0;
    });
    cleared.sort(function (a, b) {
      if (a.inventory.name < b.inventory.name) return -1;
      if (a.inventory.name > b.inventory.name) return 1;
      if ((a.cve_id || "") < (b.cve_id || "")) return -1;
      if ((a.cve_id || "") > (b.cve_id || "")) return 1;
      return 0;
    });
    return { affected: affected, cleared: cleared };
  }

  return {
    parseInventoryCsv: parseInventoryCsv,
    matchInventory: matchInventory,
    cmpVersion: cmpVersion
  };
});
