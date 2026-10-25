(function () {
  var catalog = [];
  var PAGE = 25;

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function renderPreview(rows) {
    var wrap = document.getElementById("preview");
    wrap.replaceChildren();
    var showWhere = rows.some(function (row) { return row.host || row.port; });
    var table = el("table");
    var head = el("tr");
    var labels = ["Name", "Vendor", "Version"];
    if (showWhere) labels.push("Host", "Port");
    labels.forEach(function (label) {
      head.appendChild(el("th", null, label));
    });
    var thead = el("thead");
    thead.appendChild(head);
    table.appendChild(thead);
    var body = el("tbody");
    rows.forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", null, row.name));
      tr.appendChild(el("td", null, row.vendor || "—"));
      tr.appendChild(el("td", null, row.version || "—"));
      if (showWhere) {
        tr.appendChild(el("td", null, row.host || "—"));
        tr.appendChild(el("td", null, row.port || "—"));
      }
      body.appendChild(tr);
    });
    table.appendChild(body);
    wrap.appendChild(el("h2", null, "Inventory on this device"));
    wrap.appendChild(table);
  }

  function addCells(tr, values) {
    values.forEach(function (value) { tr.appendChild(el("td", null, value)); });
  }

  function renderResults(result) {
    var root = document.getElementById("results");
    root.replaceChildren();
    var shown = result.affected.slice(0, result._limit || PAGE);
    root.appendChild(el("h2", null, "What to patch first"));
    root.appendChild(el(
      "p",
      "status",
      result.affected.length
        ? shown.length + " of " + result.affected.length + " matches, highest score first."
        : "Nothing in the catalog matched this inventory."
    ));
    if (shown.length) {
      var table = el("table");
      var head = el("tr");
      ["Score", "Your item", "Record", "How sure", "What to do"].forEach(function (label) {
        head.appendChild(el("th", null, label));
      });
      var thead = el("thead");
      thead.appendChild(head);
      table.appendChild(thead);
      var body = el("tbody");
      shown.forEach(function (item) {
        var tr = el("tr");
        var yours = item.inventory.name + (item.inventory.version ? " " + item.inventory.version : "");
        if (item.inventory.host) {
          yours += " · " + item.inventory.host + (item.inventory.port ? ":" + item.inventory.port : "");
        }
        var record = item.cve_id + " · " + (item.product || item.title || "");
        if (item.kev_date_added) record += " · catalog date " + item.kev_date_added;
        addCells(tr, [
          Number(item.score || 0).toFixed(1),
          yours,
          record,
          item.confidence_label,
          item.what_to_do
        ]);
        body.appendChild(tr);
      });
      table.appendChild(body);
      root.appendChild(table);
    }
    if (result.affected.length > shown.length) {
      var more = el("button", "secondary");
      more.type = "button";
      more.textContent = "Show all " + result.affected.length + " matches";
      more.addEventListener("click", function () {
        result._limit = result.affected.length;
        renderResults(result);
      });
      root.appendChild(more);
    }

    function sameRow(item, row) {
      return item.inventory.name === row.name
        && item.inventory.vendor === (row.vendor || "")
        && item.inventory.version === (row.version || "")
        && (item.inventory.host || "") === (row.host || "")
        && (item.inventory.port || "") === (row.port ? String(row.port) : "");
    }
    var unmatched = result._rows.filter(function (row) {
      var mentioned = result.affected.concat(result.cleared);
      return !mentioned.some(function (item) { return sameRow(item, row); });
    });
    if (unmatched.length) {
      root.appendChild(el("h2", null, "No catalog match"));
      var list = el("ul");
      unmatched.forEach(function (row) {
        var where = row.host ? " on " + row.host + (row.port ? ":" + row.port : "") : "";
        list.appendChild(el("li", null, row.name + (row.vendor ? " (" + row.vendor + ")" : "") + where + " — nothing in this catalog matched the name."));
      });
      root.appendChild(list);
    }

    if (result.cleared.length) {
      var details = el("details");
      details.appendChild(el("summary", null, result.cleared.length + " name matches sat outside the published version ranges"));
      var note = el("p", null, "These are hidden from the patch list. The range list is capped and approximate, so a cleared row can still be wrong.");
      details.appendChild(note);
      var clearedList = el("ul");
      result.cleared.slice(0, 30).forEach(function (item) {
        clearedList.appendChild(el("li", null, item.inventory.name + " " + item.inventory.version + " · " + item.cve_id));
      });
      details.appendChild(clearedList);
      root.appendChild(details);
    }
  }

  function rowsFromText(text) {
    var trimmed = String(text || "").replace(/^\uFEFF/, "").trim();
    if (trimmed.charAt(0) === "<") {
      if (!window.ThreatNmap) throw new Error("The nmap reader did not load.");
      return window.ThreatNmap.inventoryRows(window.ThreatNmap.parseNmapXml(trimmed));
    }
    return window.ThreatMatch.parseInventoryCsv(text);
  }

  function run(text) {
    var rows;
    try {
      rows = rowsFromText(text);
    } catch (error) {
      document.getElementById("results").replaceChildren(el("p", "banner", error.message));
      return;
    }
    renderPreview(rows);
    var result = window.ThreatMatch.matchInventory(rows, catalog);
    result._rows = rows;
    result._limit = PAGE;
    renderResults(result);
  }

  function loadSample() {
    fetch("sample-inventory.csv")
      .then(function (response) { return response.text(); })
      .then(run)
      .catch(function () {
        document.getElementById("results").replaceChildren(el("p", null, "The sample CSV could not be loaded."));
      });
  }

  function loadSampleScan() {
    fetch("sample-nmap.xml")
      .then(function (response) { return response.text(); })
      .then(run)
      .catch(function () {
        document.getElementById("results").replaceChildren(el("p", null, "The sample scan could not be loaded. Serve this folder with a local web server, then try again."));
      });
  }

  document.getElementById("sample").addEventListener("click", loadSample);
  document.getElementById("sample-scan").addEventListener("click", loadSampleScan);
  document.getElementById("file").addEventListener("change", function (event) {
    var file = event.target.files && event.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () { run(String(reader.result || "")); };
    reader.readAsText(file);
  });

  fetch("data/catalog.json")
    .then(function (response) {
      if (!response.ok) throw new Error("missing");
      return response.json();
    })
    .then(function (payload) {
      catalog = payload.items || [];
      document.getElementById("status").textContent = catalog.length + " catalog records loaded in this browser. Choose a CSV or nmap XML, or load a sample. Nothing is uploaded.";
    })
    .catch(function () {
      document.getElementById("status").textContent = "The catalog file is missing. Run python3 threat-brief/collect.py, then reload this page.";
    });
})();
