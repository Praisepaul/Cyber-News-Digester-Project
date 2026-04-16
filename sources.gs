function fetchRss(url) {
  const res = UrlFetchApp.fetch(url, {
    muteHttpExceptions: true,
    followRedirects: true,
    timeout: 20000
  });

  if (res.getResponseCode() !== 200) {
    throw new Error("Fetch failed: " + res.getResponseCode());
  }

  const xml = XmlService.parse(res.getContentText());
  const root = xml.getRootElement();
  const rootName = root.getName();

  let entries = [];

  // RSS 2.0
  if (rootName === "rss") {
    const channel = root.getChild("channel");
    if (!channel) return [];
    entries = channel.getChildren("item").slice(0, 20).map(i => ({
      title: i.getChildText("title"),
      url: i.getChildText("link"),
      published: i.getChildText("pubDate"),
      description: i.getChildText("description") || ""
    }));
  }

  // Atom
  if (rootName === "feed") {
    const ns = root.getNamespace();
    entries = root.getChildren("entry", ns).slice(0, 20).map(e => ({
      title: e.getChildText("title", ns),
      url: e.getChild("link", ns)?.getAttribute("href")?.getValue(),
      published: e.getChildText("published", ns),
      description: e.getChildText("summary", ns) || ""
    }));
  }

  return entries.filter(e => e.title && e.url);
}

function fetchRssSource(feedUrl, sourceName) {
  const entries = fetchRss(feedUrl);
  return entries.map(e => normalize(e, sourceName));
}


function fetchGitHub(keyword) {
  const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(keyword)}&sort=updated`;
  const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) return [];

  const data = JSON.parse(res.getContentText());
  return data.items.slice(0, 10).map(r => ({
    title: r.full_name,
    url: r.html_url,
    published: r.updated_at,
    description: r.description || ""
  }));
}
