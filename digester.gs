function dailyRun() {
  const ss = SpreadsheetApp.getActive();
  const srcSheet = ss.getSheetByName("Sources");
  const itemSheet = ss.getSheetByName("Items");

  let existingIds = new Set();
  const lastRow = itemSheet.getLastRow();
  if (lastRow > 1) {
    existingIds = new Set(
      itemSheet.getRange(2, 1, lastRow - 1, 1).getValues().flat()
    );
  }

  const sources = srcSheet.getRange(2, 1, srcSheet.getLastRow() - 1, 5).getValues();
  let collected = [];

  for (const [enabled, type, name, url] of sources) {
  if (!enabled) continue;

  Logger.log(`Starting source: ${name} (${type})`);

  let items = [];
  const start = new Date();

  try {
    if (type === "kev") items = fetchCisaKev(url);
    else if (type === "nvd") items = fetchNvdCves(url);
    else if (type === "msrc") items = fetchMsrc(url);
    else if (type === "watch") {
  if (!url) {
    Logger.log(`Skipping watch source "${name}" because Url/keyword is blank`);
    items = [];
  } else {
    items = fetchWatch(url);
  }
}

    else if (type === "rss") items = fetchRssSource(url, name);
    else Logger.log(`Unknown source type: ${type}`);
  } catch (e) {
    Logger.log(`ERROR ${name}: ${e.message}`);
    continue;
  }

  const duration = ((new Date()) - start) / 1000;
  Logger.log(`Finished ${name}: ${items.length} items in ${duration}s`);

  items.forEach(i => {
    if (!existingIds.has(i.id)) {
      collected.push(i);
      existingIds.add(i.id);
    }
  });
}

  if (!collected.length) return;

  collected.sort((a, b) => b.score - a.score);

const before = collected.length;

dumpAllCollected(collected);

const orgRelevant = collected.filter(isOrgRelevant);
const highRiskGlobal = collected.filter(isHighRiskGlobal);

// Merge + dedupe
const seen = new Set();
collected = [...orgRelevant, ...highRiskGlobal].filter(i => {
  if (seen.has(i.id)) return false;
  seen.add(i.id);
  return true;
});

Logger.log(
  `Relevance filter: ${before} → ${collected.length} ` +
  `(org=${orgRelevant.length}, global=${highRiskGlobal.length})`
);


if (!collected.length) {
  Logger.log("No New Incidents or Vulnerabilities Found. Have a Good day...");
  return;
}

  itemSheet.getRange(itemSheet.getLastRow() + 1, 1, collected.length, 10)
    .setValues(collected.map(i => [
      i.id, i.title, i.url, i.source, i.published,
      i.type, i.cves, i.severity, i.score, i.summary
    ]));

const emailItems = collected
  .filter(i => isOrgRelevant(i) || isHighRiskGlobal(i))
  .filter(i => isIncidentItem(i) || isVulnerabilityItem(i))
  .slice(0, 15);


Logger.log(`Email candidates: ${emailItems.length}`);
sendEmailDigest(emailItems);


}
function sendEmailDigest(items) {
  try {
    Logger.log(`sendEmailDigest called with ${items.length} items`);
    if (!items.length) return;

    let html = `
      <p>
        <b>Daily Vulnerability Intelligence</b><br>
        Full News Digest available at:
        <a href="https://docs.google.com/spreadsheets/d/1jCU2VlTG0lsaufMz02qKvVl48fBGU9ZHVZurtX2RgRg/edit?usp=sharing">
          Google Sheets
        </a>
      </p>
      <hr>
    `;

   const incidents = items.filter(isIncidentItem);
   const cves = items.filter(i => i.type !== "incident");
  const vulns = items.filter(i => !isIncidentStrict(i) && isVulnStrict(i) && !isIncidentItem(i) && isVulnerabilityItem(i));


    if (incidents.length) {
      html += `<h3>Incidents & Threats</h3>`;

      incidents.forEach(i => {
        html += `
          <p>
            <b>Title:</b> ${cleanTitle(i.title)}<br>
            <b>Published:</b> ${i.published}<br>
            <b>Summary:</b> ${i.summary}<br>
            <b>Severity:</b> ${String(i.severity).toUpperCase()}<br>
            <b>Source:</b> ${i.source}<br>
            <b>Link:</b> <a href="${i.url}">${i.url}</a>
          </p>
        `;
      });
    }

    if (cves.length) {
      html += `<h3>Relevant Vulnerabilities</h3>`;

      cves.forEach(i => {
        html += `
          <p>
            <b>Title:</b> ${cleanTitle(i.title)}<br>
            <b>Published:</b> ${i.published}<br>
            <b>Summary:</b> ${i.summary}<br>
            <b>Severity:</b> ${String(i.severity).toUpperCase()}<br>
            <b>Source:</b> ${i.source}<br>
            <b>Link:</b> <a href="${i.url}">${i.url}</a>
          </p>
        `;
      });
    }

    const subject = buildEmailSubject(items);
    Logger.log("Email subject: " + subject);

    GmailApp.sendEmail(
      Session.getActiveUser().getEmail(),
      subject,
      "Your email client does not support HTML emails.",
      { htmlBody: html }
    );

    Logger.log("Email sent successfully");
  } catch (e) {
    Logger.log("ERROR in sendEmailDigest: " + e.message);
    throw e;
  }
}
