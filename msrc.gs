function fetchMsrc(url) {
  const res = UrlFetchApp.fetch(url, {
    headers: { Accept: "application/json" },
    timeout: 20000
  });

  const data = JSON.parse(res.getContentText());
  if (!data.value) return [];

  return data.value
    .filter(v => ["Critical", "High"].includes(v.severity) && isAfterCutoff(v.publishedDate))
    .map(v => ({
      id: sha1(v.cveNumber),
      title: `${v.cveNumber} – ${v.productFamily}`,
      url: v.articleUrl,
      source: "MSRC",
      published: v.publishedDate,
      type: "msrc",
      cves: v.cveNumber,
      severity: v.severity.toLowerCase(),
      score: v.severity === "Critical" ? 90 : 75,
      summary: v.title
    }));
}
