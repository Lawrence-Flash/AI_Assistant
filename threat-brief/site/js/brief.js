(function () {
  var state = { items: [], brief: null };

  function band(item) {
    var score = Number(item.score || 0);
    if (item.in_kev || score >= 70) return { text: "Patch soon", className: "high" };
    if (score >= 40) return { text: "Check this week", className: "mid" };
    return { text: "Lower on this list", className: "low" };
  }

  function when(iso) {
    if (!iso) return "Unknown time";
    try {
      return new Intl.DateTimeFormat("en-ZA", {
        timeZone: "Africa/Johannesburg",
        dateStyle: "full",
        timeStyle: "short"
      }).format(new Date(iso)) + " SAST";
    } catch (error) {
      return iso;
    }
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function badge(className, text) {
    return el("li", className, text);
  }

  function renderCard(item) {
    var score = Number(item.score || 0);
    var label = band(item);
    var card = el("article", "card");
    var col = el("div", "score-col");
    var number = el("p", "score");
    number.textContent = score.toFixed(1);
    var outOf = el("span", null, "out of 100");
    number.appendChild(outOf);
    col.appendChild(number);
    col.appendChild(el("p", "band " + label.className, label.text));
    card.appendChild(col);

    var body = el("div");
    var title = item.kind === "news" ? item.title : (item.cve_id + " — " + (item.title || item.product || ""));
    body.appendChild(el("h2", null, title));
    var badges = el("ul", "badges");
    badges.appendChild(badge("", item.kind === "news" ? "News" : "CVE"));
    if (item.in_kev) badges.appendChild(badge("kev", "Known exploited"));
    if (item.severity) badges.appendChild(badge("", "CVSS " + item.cvss + " " + item.severity));
    if (item.epss != null) badges.appendChild(badge("", "EPSS " + Math.round(item.epss * 100) + "%"));
    (item.smb_matches || []).forEach(function (name) {
      badges.appendChild(badge("smb", name));
    });
    body.appendChild(badges);
    body.appendChild(el("p", "summary", item.summary || ""));
    var action = el("p", "action");
    action.appendChild(el("strong", null, "What to do. "));
    action.appendChild(document.createTextNode(item.what_to_do || ""));
    body.appendChild(action);

    var why = el("details");
    why.appendChild(el("summary", null, "Why this score"));
    var reasons = el("ul", "reasons");
    (item.reasons || []).forEach(function (reason) {
      reasons.appendChild(el("li", null, reason));
    });
    why.appendChild(reasons);
    if (item.references && item.references.length) {
      var links = el("ul", "refs");
      item.references.forEach(function (ref) {
        var li = el("li");
        var a = el("a", null, ref.label || ref.url);
        a.href = ref.url;
        a.rel = "noopener noreferrer";
        li.appendChild(a);
        links.appendChild(li);
      });
      why.appendChild(links);
    }
    body.appendChild(why);
    card.appendChild(body);
    return card;
  }

  function selected() {
    var query = document.getElementById("q").value.trim().toLowerCase();
    var min = Number(document.getElementById("min").value || 0);
    var kind = document.getElementById("kind").value;
    var profile = document.getElementById("profile").value;
    var kevOnly = document.getElementById("kev").checked;
    var smbOnly = document.getElementById("smb").checked;
    return state.items.filter(function (item) {
      if (item.score < min) return false;
      if (kind !== "all" && item.kind !== kind) return false;
      if (kevOnly && !item.in_kev) return false;
      if (smbOnly && !(item.smb_matches || []).length) return false;
      if (profile && (item.smb_matches || []).indexOf(profile) === -1) return false;
      if (!query) return true;
      var blob = [item.title, item.cve_id, item.vendor, item.product, item.summary, item.description, (item.smb_matches || []).join(" ")]
        .join(" ")
        .toLowerCase();
      return blob.indexOf(query) !== -1;
    });
  }

  function draw() {
    var list = document.getElementById("list");
    var items = selected();
    list.replaceChildren();
    document.getElementById("count").textContent = items.length + " shown of " + state.items.length + ".";
    if (!items.length) {
      list.appendChild(el("p", "status", "Nothing in today's brief matches these filters."));
      return;
    }
    items.forEach(function (item) { list.appendChild(renderCard(item)); });
  }

  function fillProfiles(items) {
    var select = document.getElementById("profile");
    var names = {};
    items.forEach(function (item) {
      (item.smb_matches || []).forEach(function (name) { names[name] = true; });
    });
    Object.keys(names).sort().forEach(function (name) {
      var option = el("option", null, name);
      option.value = name;
      select.appendChild(option);
    });
  }

  function showBrief(brief) {
    state.brief = brief;
    state.items = brief.items || [];
    document.getElementById("status").classList.add("hidden");
    var meta = document.getElementById("meta");
    meta.classList.remove("hidden");
    meta.textContent = when(brief.generated_at)
      + " · " + ((brief.counts || {}).brief_cves || 0) + " CVEs and "
      + ((brief.counts || {}).brief_news || 0) + " news items · mode " + (brief.mode || "unknown");
    var warnings = document.getElementById("warnings");
    (brief.warnings || []).forEach(function (warning) {
      var box = el("div", "banner");
      box.appendChild(el("p", null, warning));
      warnings.appendChild(box);
    });
    fillProfiles(state.items);
    document.getElementById("filters").classList.remove("hidden");
    document.getElementById("count").classList.remove("hidden");
    var formula = document.getElementById("formula");
    formula.classList.remove("hidden");
    var summary = el("summary", null, "How the score is calculated");
    formula.appendChild(summary);
    var text = (brief.formula && brief.formula.summary) || "The formula was not included in this data file.";
    formula.appendChild(el("p", null, text));
    formula.appendChild(el("p", null, "The words \"Patch soon\", \"Check this week\", and \"Lower on this list\" are labels for reading the page. They are not extra points. A known-exploited item is labelled \"Patch soon\" even when CVSS was missing, because the catalog already says attackers are using it."));
    if (brief.matching_note) formula.appendChild(el("p", null, brief.matching_note));
    ["q", "min", "kind", "profile", "kev", "smb"].forEach(function (id) {
      document.getElementById(id).addEventListener("input", draw);
    });
    draw();
  }

  fetch("data/brief.json")
    .then(function (response) {
      if (!response.ok) throw new Error("HTTP " + response.status);
      return response.json();
    })
    .then(showBrief)
    .catch(function () {
      document.getElementById("status").textContent = "Today's brief is not in data/brief.json yet. From the repository root, run: python3 threat-brief/collect.py";
    });
})();
