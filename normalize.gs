function extractCVEs(text) {
  const m = text.match(/CVE-\d{4}-\d{4,7}/gi);
  return m ? [...new Set(m)] : [];
}

function detectType(text) {
  if (/advisory|security update/i.test(text)) return "advisory";
  if (/exploit|poc/i.test(text)) return "exploit";
  if (/research|analysis/i.test(text)) return "research";
  return "news";
}

function buildSummary(raw) {
  const t = raw.description.replace(/<[^>]+>/g, '');
  return t.length > 300 ? t.substring(0, 300) + "…" : t;
}

function normalize(raw, source) {
  const base = (raw.title + cleanUrl(raw.url)).toLowerCase();
  return {
    id: sha1(base),
    title: raw.title,
    url: cleanUrl(raw.url),
    source: source,
    published: raw.published || nowIso(),
    type: detectType(raw.title),
    cves: extractCVEs(raw.title + " " + raw.description).join(","),
    severity: "unknown",
    score: 0,
    summary: buildSummary(raw),
    sent: false
  };
}
