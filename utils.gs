function sha1(input) {
  return Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_1,
    input
  ).map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

function extractCVEs(text) {
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi);
  return matches ? [...new Set(matches)] : [];
}

function cleanTitle(text, maxLen = 120) {
  if (!text) return "";

  text = String(text).replace(/\s+/g, " ").trim();

  if (text.length <= maxLen) return text;

  const truncated = text.slice(0, maxLen);
  const lastSpace = truncated.lastIndexOf(" ");

  return (lastSpace > 0 ? truncated.slice(0, lastSpace) : truncated) + "…";
}

function buildEmailSubject(items) {
  if (!Array.isArray(items) || items.length === 0) {
    return "Daily Vulnerability Intelligence";
  }

  const counts = {
    critical: 0,
    high: 0,
    incident: 0
  };

  items.forEach(i => {
    if (i.type === "incident") counts.incident++;
    else if (i.severity === "critical") counts.critical++;
    else if (i.severity === "high") counts.high++;
  });

  const parts = [];

  if (counts.critical) parts.push(`${counts.critical} Critical`);
  if (counts.high) parts.push(`${counts.high} High`);
  if (counts.incident) parts.push(`${counts.incident} Incident`);

  return parts.length
    ? `Daily Vulnerability Intelligence – ${parts.join(", ")}`
    : "Daily Vulnerability Intelligence";
}

const CUTOFF_DATE = new Date("2025-12-01T00:00:00Z");

function isAfterCutoff(dateValue) {
  if (!dateValue) return false;
  const d = new Date(dateValue);
  return !isNaN(d) && d >= CUTOFF_DATE;
}

function cleanUrl(url) {
  if (!url) return "";

  url = String(url).trim();

  // Fix common RSS oddities
  url = url.replace(/&amp;/g, "&");

  // Drop trackers and fragments (optional, but helps dedupe)
  url = url.split("#")[0];

  try {
    const u = new URL(url);

    // Remove common tracking params
    const drop = [
      "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
      "gclid", "fbclid", "mc_cid", "mc_eid", "ref", "ref_src", "cmpid"
    ];
    drop.forEach(p => u.searchParams.delete(p));

    // Return without trailing slash (except domain root)
    let out = u.toString();
    if (out.endsWith("/") && u.pathname !== "/") out = out.slice(0, -1);
    return out;
  } catch (e) {
    // If URL() parsing fails, just return a cleaned string
    return url;
  }
}

function containsAny(text, terms) {
  if (!text) return false;
  const t = String(text).toLowerCase();
  return terms.some(x => t.includes(String(x).toLowerCase()));
}

function matchesAny(text, regexes) {
  if (!text) return false;
  const t = String(text);
  return regexes.some(r => r.test(t));
}


function dumpAllCollected(items, sheetName = "DEBUG_All_Found") {
  if (!items || !items.length) {
    Logger.log("DEBUG dump: no items to display");
    return;
  }

  const ss = SpreadsheetApp.getActive();
  let sh = ss.getSheetByName(sheetName);

  if (!sh) {
    sh = ss.insertSheet(sheetName);
    sh.appendRow([
      "Source",
      "Type",
      "Title",
      "Published",
      "URL",
      "Summary",
      "CVEs"
    ]);
  }

  // Clear old debug rows (keep header)
  if (sh.getLastRow() > 1) {
    sh.getRange(2, 1, sh.getLastRow() - 1, 7).clearContent();
  }

  const rows = items.map(i => [
    i.source,
    i.type,
    i.title,
    i.published,
    i.url,
    i.summary,
    i.cves
  ]);

  sh.getRange(2, 1, rows.length, 7).setValues(rows);

  Logger.log(`DEBUG dump: wrote ${rows.length} items to sheet "${sheetName}"`);
}

