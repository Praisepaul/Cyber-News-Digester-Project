function fetchCisaKev(url) {
  const res = UrlFetchApp.fetch(url, { timeout: 20000 });
  const data = JSON.parse(res.getContentText());

  return data.vulnerabilities
    .filter(v => isAfterCutoff(v.dateAdded))
    .map(v => ({
      id: sha1(v.cveID),
      titleReminder: `${v.cveID} – ${v.vendorProject} ${v.product}`,
      title: `${v.cveID} – ${v.vendorProject} ${v.product}`,
      url: `https://www.cve.org/CVERecord?id=${v.cveID}`,
      source: "CISA KEV",
      published: v.dateAdded,
      type: "kev",
      cves: v.cveID,
      severity: "critical",
      score: 100,
      summary: `Actively exploited vulnerability. ${v.shortDescription}`
    }));
}
