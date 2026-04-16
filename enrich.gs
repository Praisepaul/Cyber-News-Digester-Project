function inferSeverity(item) {
  if (/exploited|in the wild|zero[- ]day|0day/i.test(item.title)) return "critical";
  if (item.cves) return "high";
  if (/rce|auth bypass|privilege escalation/i.test(item.title)) return "high";
  return "medium";
}
