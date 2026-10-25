/* Turn nmap XML into inventory rows for the "Am I affected?" page.
   Keep the name rules in step with threat-brief/collector/nmapxml.py.
   The file stays in the browser. This does not contact a network. */
(function (root, factory) {
  var api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.ThreatNmap = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  var PRODUCT_NAMES = {
    fortios: "FortiOS",
    fortigate: "FortiGate",
    fortiproxy: "FortiProxy",
    routeros: "RouterOS",
    openssh: "OpenSSH",
    openssl: "OpenSSL",
    wordpress: "WordPress",
    woocommerce: "WooCommerce",
    exchange_server: "Exchange Server",
    http_server: "HTTP Server",
    mysql: "MySQL",
    mariadb: "MariaDB",
    postgresql: "PostgreSQL",
    windows: "Windows",
    windows_10: "Windows 10",
    windows_11: "Windows 11",
    windows_server_2012: "Windows Server 2012",
    windows_server_2016: "Windows Server 2016",
    windows_server_2019: "Windows Server 2019",
    windows_server_2022: "Windows Server 2022"
  };
  var VENDOR_NAMES = {
    microsoft: "Microsoft",
    fortinet: "Fortinet",
    mikrotik: "MikroTik",
    wordpress: "WordPress",
    openbsd: "OpenBSD",
    apache: "Apache",
    oracle: "Oracle",
    linux: "Linux",
    "tp-link": "TP-Link",
    tplink: "TP-Link",
    ietf: "IETF"
  };

  function decodeXml(value) {
    return String(value || "")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&amp;/g, "&");
  }

  function unquote(value) {
    var text = decodeXml(value || "").trim();
    try {
      return decodeURIComponent(text);
    } catch (error) {
      return text;
    }
  }

  function field(value) {
    var text = unquote(value);
    if (text === "*" || text === "-" || text === "") return "";
    return text;
  }

  function titleTokens(raw) {
    return String(raw || "")
      .replace(/_/g, " ")
      .split(/\s+/)
      .filter(function (part) { return part; })
      .map(function (part) {
        if (/^[a-z]+$/.test(part)) return part.charAt(0).toUpperCase() + part.slice(1);
        return part;
      })
      .join(" ");
  }

  function displayProduct(raw) {
    var key = String(raw || "").trim().toLowerCase();
    if (PRODUCT_NAMES[key]) return PRODUCT_NAMES[key];
    return titleTokens(raw);
  }

  function displayVendor(raw) {
    var key = String(raw || "").trim().toLowerCase();
    if (VENDOR_NAMES[key]) return VENDOR_NAMES[key];
    return titleTokens(raw);
  }

  function splitCpe(criteria) {
    var parts = [];
    var buffer = "";
    for (var index = 0; index < criteria.length; index += 1) {
      var char = criteria.charAt(index);
      if (char === "\\" && index + 1 < criteria.length) {
        buffer += criteria.charAt(index + 1);
        index += 1;
        continue;
      }
      if (char === ":") {
        parts.push(buffer);
        buffer = "";
      } else {
        buffer += char;
      }
    }
    parts.push(buffer);
    return parts;
  }

  function parseCpe(cpe) {
    var text = unquote(cpe);
    var vendor = "";
    var product = "";
    var version = "";
    if (text.indexOf("cpe:2.3:") === 0) {
      var parts = splitCpe(text);
      if (parts.length < 5) return null;
      vendor = parts[3];
      product = parts[4];
      version = parts.length > 5 ? parts[5] : "";
    } else if (text.indexOf("cpe:/") === 0) {
      var old = text.split(":");
      vendor = old.length > 2 ? old[2] : "";
      product = old.length > 3 ? old[3] : "";
      version = old.length > 4 ? old[4] : "";
    } else {
      return null;
    }
    vendor = field(vendor);
    product = field(product);
    version = field(version);
    if (!product) return null;
    return { vendor: displayVendor(vendor), product: displayProduct(product), version: version };
  }

  function vendorFromProduct(product, ostype) {
    var lowered = String(product || "").toLowerCase();
    if (lowered.indexOf("microsoft") === 0 || String(ostype || "").toLowerCase() === "windows") return "Microsoft";
    if (lowered.indexOf("fortinet") === 0 || lowered.indexOf("fortios") !== -1 || lowered.indexOf("fortigate") !== -1) return "Fortinet";
    if (lowered.indexOf("mikrotik") !== -1 || lowered.indexOf("routeros") !== -1) return "MikroTik";
    if (lowered.indexOf("wordpress") === 0) return "WordPress";
    if (lowered.indexOf("tp-link") !== -1 || lowered.indexOf("tplink") !== -1) return "TP-Link";
    return "";
  }

  function rowsForService(host, service) {
    var base = {
      host: host.ip || "",
      port: String(service.port || ""),
      protocol: service.protocol || "",
      service: service.name || ""
    };
    var rows = [];
    (service.cpes || []).forEach(function (cpe) {
      var parsed = parseCpe(cpe);
      if (!parsed) return;
      rows.push({
        name: parsed.product,
        vendor: parsed.vendor,
        version: parsed.version,
        host: base.host,
        port: base.port,
        protocol: base.protocol,
        service: base.service,
        source: "cpe"
      });
    });
    if (rows.length) return rows;
    var product = String(service.product || "").trim();
    if (!product) return [];
    var vendor = vendorFromProduct(product, service.ostype || "");
    var name = product;
    if (vendor && name.toLowerCase().indexOf(vendor.toLowerCase() + " ") === 0) {
      name = name.slice(vendor.length + 1).trim() || product;
    }
    return [{
      name: name.indexOf("_") !== -1 ? displayProduct(name.replace(/ /g, "_")) : name,
      vendor: vendor,
      version: String(service.version || "").trim(),
      host: base.host,
      port: base.port,
      protocol: base.protocol,
      service: base.service,
      source: "banner"
    }];
  }

  function inventoryRows(report) {
    var rows = [];
    var seen = {};
    (report.hosts || []).forEach(function (host) {
      if (host.status !== "up") return;
      (host.services || []).forEach(function (service) {
        if (service.state !== "open") return;
        rowsForService(host, service).forEach(function (item) {
          var key = [item.host, item.port, item.protocol, item.name.toLowerCase(), item.vendor.toLowerCase(), item.version.toLowerCase()].join("|");
          if (seen[key]) return;
          seen[key] = true;
          rows.push(item);
        });
      });
    });
    return rows;
  }

  function attr(tag, name) {
    var match = new RegExp("\\b" + name + "\\s*=\\s*\"([^\"]*)\"", "i").exec(tag || "");
    return match ? decodeXml(match[1]) : "";
  }

  function parsePortBlock(block) {
    var open = (block.match(/<port\b[^>]*>/i) || [""])[0];
    var stateTag = (block.match(/<state\b[^>]*\/?>/i) || [""])[0];
    var serviceTag = (block.match(/<service\b[^>]*\/?>/i) || [""])[0];
    var cpes = [];
    var cpeRe = /<cpe>([\s\S]*?)<\/cpe>/gi;
    var found;
    while ((found = cpeRe.exec(block))) cpes.push(decodeXml(found[1]).trim());
    return {
      port: parseInt(attr(open, "portid") || "0", 10) || 0,
      protocol: attr(open, "protocol"),
      state: attr(stateTag, "state"),
      name: attr(serviceTag, "name"),
      product: attr(serviceTag, "product"),
      version: attr(serviceTag, "version"),
      extrainfo: attr(serviceTag, "extrainfo"),
      ostype: attr(serviceTag, "ostype"),
      tunnel: attr(serviceTag, "tunnel"),
      cpes: cpes
    };
  }

  function parseHostBlock(block) {
    var statusTag = (block.match(/<status\b[^>]*\/?>/i) || [""])[0];
    var ip = "";
    var addresses = [];
    var addrRe = /<address\b[^>]*\/?>/gi;
    var found;
    while ((found = addrRe.exec(block))) {
      var address = { addr: attr(found[0], "addr"), type: attr(found[0], "addrtype"), vendor: attr(found[0], "vendor") };
      addresses.push(address);
      if (!ip && address.type === "ipv4") ip = address.addr;
    }
    if (!ip) {
      for (var i = 0; i < addresses.length; i += 1) {
        if (addresses[i].type !== "mac" && addresses[i].addr) {
          ip = addresses[i].addr;
          break;
        }
      }
    }
    var hostnames = [];
    var nameRe = /<hostname\b[^>]*\/?>/gi;
    while ((found = nameRe.exec(block))) {
      var hostname = attr(found[0], "name");
      if (hostname) hostnames.push(hostname);
    }
    var services = [];
    var portRe = /<port\b[^>]*>[\s\S]*?<\/port>/gi;
    while ((found = portRe.exec(block))) services.push(parsePortBlock(found[0]));
    return {
      ip: ip,
      addresses: addresses,
      hostnames: hostnames,
      status: attr(statusTag, "state") || "unknown",
      services: services
    };
  }

  function nmaprunAttrs(xml) {
    var tag = (String(xml).match(/<nmaprun\b[^>]*>/i) || [""])[0];
    return { scanner: attr(tag, "scanner"), args: attr(tag, "args"), version: attr(tag, "version") };
  }

  function parseWithRegex(xmlText) {
    var xml = String(xmlText || "");
    if (!/<nmaprun[\s>]|<host[\s>]/i.test(xml)) {
      throw new Error("This XML does not look like an nmap report.");
    }
    var hosts = [];
    var hostRe = /<host\b[^>]*>([\s\S]*?)<\/host>/gi;
    var found;
    while ((found = hostRe.exec(xml))) hosts.push(parseHostBlock(found[1]));
    var meta = nmaprunAttrs(xml);
    return { scanner: meta.scanner, args: meta.args, version: meta.version, hosts: hosts };
  }

  function textOf(node) {
    return node && node.textContent ? String(node.textContent).trim() : "";
  }

  function parseWithDom(xmlText) {
    var doc = new DOMParser().parseFromString(String(xmlText || ""), "text/xml");
    if (!doc || doc.getElementsByTagName("parsererror").length) return null;
    var root = doc.documentElement;
    if (!root || (root.localName !== "nmaprun" && root.localName !== "host")) return null;
    var hostNodes = root.localName === "nmaprun" ? root.getElementsByTagName("host") : [root];
    var hosts = [];
    for (var h = 0; h < hostNodes.length; h += 1) {
      var node = hostNodes[h];
      if (node.parentElement && node.parentElement.localName !== "nmaprun" && root.localName === "nmaprun") continue;
      var status = node.getElementsByTagName("status")[0];
      var ip = "";
      var addresses = [];
      var addressNodes = node.getElementsByTagName("address");
      for (var a = 0; a < addressNodes.length; a += 1) {
        if (addressNodes[a].parentElement !== node) continue;
        var address = {
          addr: addressNodes[a].getAttribute("addr") || "",
          type: addressNodes[a].getAttribute("addrtype") || "",
          vendor: addressNodes[a].getAttribute("vendor") || ""
        };
        addresses.push(address);
        if (!ip && address.type === "ipv4") ip = address.addr;
      }
      if (!ip) {
        for (var i = 0; i < addresses.length; i += 1) {
          if (addresses[i].type !== "mac" && addresses[i].addr) {
            ip = addresses[i].addr;
            break;
          }
        }
      }
      var hostnames = [];
      var hostnameNodes = node.getElementsByTagName("hostname");
      for (var n = 0; n < hostnameNodes.length; n += 1) {
        var hostname = hostnameNodes[n].getAttribute("name");
        if (hostname) hostnames.push(hostname);
      }
      var services = [];
      var portNodes = node.getElementsByTagName("port");
      for (var p = 0; p < portNodes.length; p += 1) {
        var portNode = portNodes[p];
        if (portNode.parentElement && portNode.parentElement.parentElement !== node) continue;
        var stateNode = portNode.getElementsByTagName("state")[0];
        var serviceNode = portNode.getElementsByTagName("service")[0];
        var cpes = [];
        if (serviceNode) {
          var cpeNodes = serviceNode.getElementsByTagName("cpe");
          for (var c = 0; c < cpeNodes.length; c += 1) cpes.push(textOf(cpeNodes[c]));
        }
        services.push({
          port: parseInt(portNode.getAttribute("portid") || "0", 10) || 0,
          protocol: portNode.getAttribute("protocol") || "",
          state: stateNode ? (stateNode.getAttribute("state") || "") : "",
          name: serviceNode ? (serviceNode.getAttribute("name") || "") : "",
          product: serviceNode ? (serviceNode.getAttribute("product") || "") : "",
          version: serviceNode ? (serviceNode.getAttribute("version") || "") : "",
          extrainfo: serviceNode ? (serviceNode.getAttribute("extrainfo") || "") : "",
          ostype: serviceNode ? (serviceNode.getAttribute("ostype") || "") : "",
          tunnel: serviceNode ? (serviceNode.getAttribute("tunnel") || "") : "",
          cpes: cpes
        });
      }
      hosts.push({
        ip: ip,
        addresses: addresses,
        hostnames: hostnames,
        status: status ? (status.getAttribute("state") || "unknown") : "unknown",
        services: services
      });
    }
    return {
      scanner: root.getAttribute("scanner") || "",
      args: root.getAttribute("args") || "",
      version: root.getAttribute("version") || "",
      hosts: hosts
    };
  }

  function parseNmapXml(xmlText) {
    if (typeof DOMParser !== "undefined") {
      var parsed = parseWithDom(xmlText);
      if (parsed && parsed.hosts.length) return parsed;
      if (parsed && /<nmaprun[\s>]|<host[\s>]/i.test(String(xmlText || ""))) return parsed;
    }
    return parseWithRegex(xmlText);
  }

  return {
    parseNmapXml: parseNmapXml,
    parseWithRegex: parseWithRegex,
    inventoryRows: inventoryRows,
    parseCpe: parseCpe
  };
});
