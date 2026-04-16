const WATCH_SOURCES = [
  "https://feeds.feedburner.com/TheHackersNews",
  "https://www.bleepingcomputer.com/feed/",
  "https://www.darkreading.com/rss.xml",
  "https://www.cybersecuritydive.com/feeds/news/",
  "https://www.securityweek.com/feed",
  "https://cybersecuritynews.com/feed/",
  "https://www.bleepingcomputer.com/feed/tag/vulnerability"
  ];

const WATCH_KEYWORDS = [
  // exploitation / urgency
  "zero-day",
  "zero day",
  "exploited",
  "actively exploited",
  "in the wild",
  "pre-auth",
  "unauthenticated",
  "rce",
  "remote code execution",
  "auth bypass",
  "privilege escalation",
  "wormable",
  "supply chain attack",
  "malicious update",
  "backdoor",
  "ransomware",

  // CVE / vuln language
  "cve-",
  "vulnerability",
  "security flaw",
  "patch",
  "patched",
  "security update",
  "hotfix",

  // core tech / platforms
  "windows",
  "linux",
  "ubuntu",
  "macos",
  "chrome",
  "chromium",
  "firefox",
  "safari",
  "docker",
  "kubernetes",
  "cloudflare",
  "github",
  "git",
  "aws",
  "azure",
  "openai",
  "chatgpt",
  "mongodb",
  "redis",
  "nginx",
  "apache",
  "slack",
  "jira",
  "atlassian",
  "vscode"
];


function fetchWatch(keyword) {
  keyword = String(keyword || "").trim();
  if (!keyword) {
    Logger.log("Watch source skipped: missing keyword");
    return [];
  }
  
  let results = [];

  WATCH_SOURCES.forEach(feed => {
    let items = [];
    try {
      const res = UrlFetchApp.fetch(feed, {
        muteHttpExceptions: true,
        timeout: 20000, // Increased timeout for slower feeds
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
      });

      if (res.getResponseCode() !== 200) return;

      const xml = XmlService.parse(res.getContentText());
      const root = xml.getRootElement();
      
      // Basic RSS 2.0 Parsing
      const channel = root.getChild("channel");
      if (channel) {
        items = channel.getChildren("item").slice(0, 20).map(i => ({
          title: i.getChildText("title"),
          url: i.getChildText("link"),
          published: i.getChildText("pubDate"),
          description: i.getChildText("description") || ""
        }));
      }
    } catch (e) {
      Logger.log(`Error fetching ${feed}: ${e.message}`);
    }

    // Filter and Normalize
    items.forEach(i => {
      if (!isAfterCutoff(i.published)) return;
      
      const text = `${i.title} ${i.description}`.toLowerCase();
      const kw = keyword.toLowerCase();
      
      // Match keyword and look for "vulnerability" context
      if (text.includes(kw)) {
        const isVuln = /(vulnerability|cve|exploit|rce|zero[- ]day|patch|security update)/i.test(text);
        
        if (isVuln) {
          results.push({
            id: sha1(keyword + i.url), // Use URL for more stable ID
            title: cleanTitle(i.title),
            url: i.url,
            source: "Security Intel",
            published: i.published,
            type: detectType(text),
            cves: extractCVEs(text).join(","),
            severity: text.includes("critical") ? "critical" : "high",
            score: text.includes("critical") ? 90 : 70,
            summary: buildSummary(i)
          });
        }
      }
    });
  });

// Deduplicate watch items by URL
const seen = new Set();
results = results.filter(item => {
  if (seen.has(item.url)) return false;
  seen.add(item.url);
  return true;
});

return results;

}
