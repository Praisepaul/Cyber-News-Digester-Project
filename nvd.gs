function fetchNvdCves(baseUrl) {
  const url = `${baseUrl}?resultsPerPage=200`;
  Logger.log("NVD URL: " + url);

  const res = UrlFetchApp.fetch(url, {
    muteHttpExceptions: true,
    timeout: 20000,
    headers: {
      "User-Agent": "VulnIntel/1.0"
    }
  });

  if (res.getResponseCode() !== 200) {
    throw new Error(`NVD fetch failed (${res.getResponseCode()})`);
  }

  const data = JSON.parse(res.getContentText());
  if (!data.vulnerabilities) return [];

  return data.vulnerabilities
   .map(v => {
  const cve = v.cve;

  if (!isAfterCutoff(cve.published)) return null;

  const metrics =
    cve.metrics?.cvssMetricV31 ||
    cve.metrics?.cvssMetricV30 ||
    [];

  if (!metrics.length) return null;

  const cvss = metrics[0].cvssData.baseScore;
  if (cvss < 8.0) return null;

  return {
    id: sha1(cve.id),
    title: `${cve.id} – ${cve.descriptions[0].value.substring(0, 120)}`,
    url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    source: "NVD",
    published: cve.published,
    type: "cve",
    cves: cve.id,
    severity: cvss >= 9 ? "critical" : "high",
    score: Math.round(cvss * 10),
    summary: cve.descriptions[0].value
  };
})
    .filter(Boolean);
}
