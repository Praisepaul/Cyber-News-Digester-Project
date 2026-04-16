const ENV_KEYWORDS = {
  windows: /windows|apple|macOS|machintosh|microsoft|win32|nt kernel|/i,
  linux: /linux|ubuntu|debian|systemd|glibc|openssl|busybox/i,
  browser: /chrome|chromium|edge|firefox|webkit|safari|brave|browser|extension|plugin/i,
  javascript: /javascript|node\.js|npm|react|typescript|vue|vite|next\.js|express/i,
  python: /python|django|flask|fastapi|pip|virtualenv|pycharm/i,
  cloud: /cloudflare|git|GitHub| GitHub Actions|aws|amazon web services?|s3|ec2|iam|lambda|kubernetes|docker|container|terraform|ansible|ArgoCD|Grafana|Oracle|OCI|OKE/i,
  ai: /openai|chatgpt|deepseek|llm|ai model|inference|prompt injection|model poisoning/i,
  security_tools: /crowdstrike|falcon|snyk|postman|vault|jumpcloud|netskope/i,
  database: /mongodb|redis|cassandra|elasticsearch/i,
  network: /reverse proxy|nginx|apache/i,
  applications: /Cursor|Slack|Figma|Postman|jira|atlassian|vscode/i
};


// Strong “this is actually a vuln/patch/exploit” signals
const VULN_SIGNALS = /(cve-\d{4}-\d{4,7}|vulnerab|security flaw|zero[- ]day|0[- ]day|in the wild|actively exploited|exploit(ed)?|poc|proof[- ]of[- ]concept|rce|remote code execution|privilege escalation|elevation of privilege|auth(entication)? bypass|pre-auth|unauthenticated|sql injection|sqli|xss|cross[- ]site scripting|csrf|ssrf|path traversal|directory traversal|deserialization|buffer overflow|heap overflow|stack overflow|use[- ]after[- ]free|memory corruption|integer overflow|race condition|sandbox escape|arbitrary file write|arbitrary file read|command injection|code injection|security update|patch(ed|es)?|hotfix|advisory|bypass(es|ed)?|backdoor)/i;


// Stuff you *don’t* want in the vuln digest (tune as you like)
const NOISE_SIGNALS = /(is offering|free to some users|discount|deal|pricing|subscription|promo|giveaway|is testing|beta|preview|feature update|new feature|review|opinion|recap|year in review|top \d+ (stories|news)|best of|roundup|lawmaker|senate|white house|policy|regulation|arrest(s|ed)?|neutraliz(ed|es)?|interpol|job scam|scammers|conference|webinar|fortinet|event)/i;


const MUST_NOT_MISS = /(cisa|kev|known exploited|exploited in the wild|actively exploited|zero[- ]day|0[- ]day|pre-auth|unauthenticated|wormable|mass exploitation|ransomware actors?|apt\d+|supply chain attack|malicious update|backdoor)/i;

const CVSS_CRITICAL_WORDS = /(critical|cvss[: ]?(9\.\d|10\.0)|severity[: ]?critical)/i;



function classifyEnvironment(item) {
  const text = `${item.title || ""} ${item.summary || ""}`.toLowerCase();
  const matches = [];

  for (const [env, regex] of Object.entries(ENV_KEYWORDS)) {
    if (regex.test(text)) matches.push(env);
  }

  return matches;
}

function isRelevant(item) {
  // Always keep incidents / watch items
  if (item.type === "incident" || item.source === "Security News") {
    return true;
  }

  const text = `${item.title || ""} ${item.summary || ""} ${item.url || ""}`;

  // Basic “is this security/vuln content?” gate
  const hasVulnSignal =
    VULN_SIGNALS.test(text) || /CVE-\d{4}-\d{4,7}/i.test(text);

  if (!hasVulnSignal) return false;

  // Lane 1: org-targeted relevance (your environments)
  const envs = classifyEnvironment(item);
  if (envs.length > 0) return true;

  // Lane 2: global “must not miss”
  // Keep only if it’s clearly high-risk even if not in your env regex.
  if (MUST_NOT_MISS.test(text)) return true;
  if (/CVE-\d{4}-\d{4,7}/i.test(text) && CVSS_CRITICAL_WORDS.test(text)) return true;

  return false;
}


function isOrgRelevant(item) {
  if (item.type === "incident" || item.source === "Security News") return true;
  const envs = classifyEnvironment(item);
  return envs.length > 0;
}

function isHighRiskGlobal(item) {
  const text = `${item.title || ""} ${item.summary || ""} ${item.url || ""}`;
  const hasVulnSignal =
    VULN_SIGNALS.test(text) || /CVE-\d{4}-\d{4,7}/i.test(text);

  if (!hasVulnSignal) return false;

  return (
    MUST_NOT_MISS.test(text) ||
    (/CVE-\d{4}-\d{4,7}/i.test(text) && CVSS_CRITICAL_WORDS.test(text))
  );
}

function isVulnerabilityItem(item) {
  const text = `${item.title || ""} ${item.summary || ""} ${item.url || ""}`;

  // Must have CVE OR explicit vuln/patch/zero-day language
  const vulnStrong =
    /CVE-\d{4}-\d{4,7}/i.test(text) ||
    /vulnerab|security flaw|zero[- ]day|0[- ]day|patch(ed|es)?|security update|hotfix|advisory|rce|remote code execution|auth(entication)? bypass|privilege escalation|elevation of privilege/i.test(text);

  if (!vulnStrong) return false;

  // Exclude policy/operations/LE/non-vuln stories that still mention “security”
  const notAVuln =
    /lawmaker|white house|senate|policy|regulation|interpol|arrest|neutraliz|scammers|job scam|forced to close|cyberattack on .*school|operation sentinel/i.test(text);

  if (notAVuln) return false;

  return true;
}

function isIncidentItem(item) {
  // Your watch items already do this, but include breach/attack/leak style RSS too
  const text = `${item.title || ""} ${item.summary || ""}`.toLowerCase();
  return (
    item.type === "incident" ||
    item.source === "Security News" ||
    /(breach|leak|stolen|ransomware|extortion|cyberattack|compromis(ed|e)|data exposure)/i.test(text)
  );
}

function isIncidentStrict(item) {
  const t = `${item.title || ""} ${item.summary || ""} ${item.url || ""}`.toLowerCase();

  // Strong incident/breach language
  const incidentSignals = /(data breach|breach(ed)?|leak(ed)?|stolen|exfiltrat(ed|ion)|compromis(ed|e)|unauthorized access|intrusion|ransomware|extortion|encrypted systems|ddos|credential stuffing|phishing campaign|supply chain attack|malware campaign|botnet|c2|command and control)/i;

  // Obvious "not an incident" news/policy content
  const noise = /(lawmaker|senate|white house|policy|regulation|overhaul|push back|industry continues|asks .* to address|tips|how to|guide|best practices|roundup|year in review|defined .* 20\d{2}|top \d+|webinar|conference|event)/i;

  if (noise.test(t)) return false;
  return incidentSignals.test(t);
}

function isVulnStrict(item) {
  const t = `${item.title || ""} ${item.summary || ""} ${item.url || ""}`.toLowerCase();

  // Must be vuln/exploit/patch content
  const vulnSignals = /(cve-\d{4}-\d{4,7}|vulnerab|security flaw|zero[- ]day|0[- ]day|exploited|in the wild|actively exploited|patch(ed|es)?|security update|hotfix|advisory|rce|remote code execution|auth(entication)? bypass|pre-auth|unauthenticated|privilege escalation|elevation of privilege|sql injection|xss|ssrf|path traversal|deserialization|use[- ]after[- ]free|memory corruption|arbitrary file (read|write)|command injection|code injection)/i;

  // Exclude generic security news/policy/roundups even if they mention "security"
  const notAVuln = /(lawmaker|senate|white house|policy|regulation|overhaul|push back|tips|how to|guide|best practices|roundup|year in review|defined .* 20\d{2}|top \d+|webinar|conference|event|asks .* to address)/i;

  if (notAVuln.test(t)) return false;
  return vulnSignals.test(t);
}

