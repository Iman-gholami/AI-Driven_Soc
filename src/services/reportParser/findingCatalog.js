const STAGE_VERSION = "docx-v6";


function enhanceReportRecordV6(report) {
  if (!report || typeof report !== "object") return report;

  if (!report.finding || report.finding.type === "unknown") {
    const titleFinding = classifyFindingV6(report.title);
    const finding = titleFinding.type !== "unknown"
      ? titleFinding
      : classifyFindingV6([report.title, report.description, report.fullText].filter(Boolean).join("\n"));

    if (finding.type !== "unknown") {
      report.finding = finding;
      report.vulnerability = vulnerabilityFromFindingV6(finding);
    }
  }

  const warnings = new Set(report.extraction?.warnings || []);
  if (report.finding?.type !== "unknown") warnings.delete("unknown_finding_type");

  report.extraction = {
    ...(report.extraction || {}),
    parserVersion: STAGE_VERSION,
    warnings: [...warnings],
  };

  return report;
}

function classifyFindingV6(value) {
  const text = normalize(value);
  const catalog = [
    // Profiled 1404 families. Keep more specific threat/network patterns before broad ones.
    {
      pattern: /آلودگی\s+به\s+بدافزار.*(?:ip\s*\/\s*domain|آدرس).*آلوده.*(?:tunnel|تونل)/,
      type: "malware_tunnel_communication",
      name: "Malware Tunnel Communication",
      category: "malware_network_activity",
      cwe: null,
    },
    {
      pattern: /ارتباط\s+مخرب.*(?:ip\s*\/\s*domain|آدرس).*مشکوک/,
      type: "suspicious_indicator_communication",
      name: "Suspicious IP/Domain Communication",
      category: "threat_communication",
      cwe: null,
    },
    {
      pattern: /ارتباط\s+مخرب.*(?:ip\s*\/\s*domain|آدرس).*آلوده/,
      type: "malicious_indicator_communication",
      name: "Malicious IP/Domain Communication",
      category: "threat_communication",
      cwe: null,
    },
    {
      pattern: /نقض\s+سیاست(?:\s*های)?\s+امنیتی.*عدم\s+مدیریت\s+رمز\s+عبور|عدم\s+مدیریت\s+رمز\s+عبور/,
      type: "password_policy_violation",
      name: "Password Policy Violation",
      category: "credential_security",
      cwe: "CWE-521",
    },
    {
      pattern: /dns.*open\s*resolver|open\s*resolver.*dns/,
      type: "open_dns_resolver",
      name: "Open DNS Resolver",
      category: "dns_misconfiguration",
      cwe: null,
    },
    {
      pattern: /wordpress\s*(?:cms)?/,
      type: "vulnerable_wordpress",
      name: "Vulnerable WordPress CMS",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /(?:نسخه\s+آسیب\s*پذیر|آسیب\s*پذیری).*xampp|xampp.*(?:نسخه\s+آسیب\s*پذیر|آسیب\s*پذیری)/,
      type: "vulnerable_xampp",
      name: "Vulnerable XAMPP",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /اخذ\s+دسترسی.*بارگذاری\s+فایل\s+غیرمجاز|بارگذاری\s+فایل\s+غیرمجاز/,
      type: "unrestricted_file_upload",
      name: "Unrestricted File Upload",
      category: "web_vulnerability",
      cwe: "CWE-434",
    },
    {
      pattern: /(?:سرویس\s+آسیب\s*پذیر|پیکربندی\s+نامناسب).*remote\s+desktop|remote\s+desktop.*(?:آسیب\s*پذیر|exposed)/,
      type: "exposed_remote_desktop",
      name: "Exposed / Vulnerable Remote Desktop",
      category: "exposed_service",
      cwe: null,
    },
    {
      pattern: /(?:نام\s+کاربری.*(?:کلمه|رمز)\s+عبور|credential).*پیش\s*فرض|default\s+credentials?/,
      type: "default_credentials",
      name: "Default Credentials",
      category: "credential_security",
      cwe: "CWE-1392",
    },
    {
      pattern: /allegro\s+rompager|rompager/,
      type: "vulnerable_rompager",
      name: "Vulnerable Allegro RomPager",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /(?:نسخه\s+آسیب\s*پذیر|آسیب\s*پذیری).*liferay|liferay.*(?:نسخه\s+آسیب\s*پذیر|آسیب\s*پذیری)/,
      type: "vulnerable_liferay",
      name: "Vulnerable Liferay",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /(?:دور\s*زدن|bypass).*کنترل\s*دسترسی.*(?:هایک\s*ویژن|hikvision)|(?:هایک\s*ویژن|hikvision).*access\s*control\s*bypass/,
      type: "hikvision_access_control_bypass",
      name: "Hikvision Access Control Bypass",
      category: "access_control",
      cwe: null,
    },
    {
      pattern: /(?:نسخه\s+آسیب\s*پذیر|استفاده\s+از\s+نسخه\s+آسیب\s*پذیر).*next\s*\.?\s*js|next\s*\.?\s*js.*(?:آسیب\s*پذیر|vulnerable)/,
      type: "vulnerable_nextjs",
      name: "Vulnerable Next.js",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /نقض\s+سیاست(?:\s*های)?\s+امنیتی.*(?:بستر\s+متن\s+آشکار|ارتباط\s+در\s+بستر\s+متن\s+آشکار)|(?:cleartext|clear\s*text).*communication/,
      type: "cleartext_communication",
      name: "Cleartext Communication",
      category: "transport_security",
      cwe: "CWE-319",
    },
    {
      pattern: /(?:سرویس\s+آسیب\s*پذیر|پیکربندی\s+نامناسب).*\bupnp\b|\bupnp\b.*(?:آسیب\s*پذیر|exposed)/,
      type: "exposed_upnp_service",
      name: "Exposed / Vulnerable UPnP Service",
      category: "exposed_service",
      cwe: null,
    },
    {
      pattern: /cisco\s+asa\s*\/\s*ftd|(?:cisco\s+)?asa\s*\/\s*ftd/,
      type: "vulnerable_cisco_asa_ftd",
      name: "Vulnerable Cisco ASA/FTD",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /zimbra\s+collaboration|(?:نسخه\s+آسیب\s*پذیر|آسیب\s*پذیری).*zimbra/,
      type: "vulnerable_zimbra",
      name: "Vulnerable Zimbra Collaboration",
      category: "vulnerable_software",
      cwe: null,
    },
    {
      pattern: /(?:افشای\s+اطلاعات\s+dns|dns.*information).*\b(?:axfr|ixfr)\b|\b(?:axfr|ixfr)\b.*dns/,
      type: "dns_zone_transfer_exposure",
      name: "DNS Zone Transfer Exposure",
      category: "dns_misconfiguration",
      cwe: null,
    },
    {
      pattern: /رفتار\s+ناهنجار.*پویش\s+نامتعارف|پویش\s+نامتعارف|unusual\s+scan(?:ning)?/,
      type: "unusual_scanning",
      name: "Unusual Scanning Activity",
      category: "network_anomaly",
      cwe: null,
    },
    {
      pattern: /عدم\s+اعمال\s+کنترل\s+امنیتی.*\btftp\b|\btftp\b.*(?:عدم\s+اعمال\s+کنترل\s+امنیتی|insecure|unprotected)/,
      type: "insecure_tftp_service",
      name: "Insecure TFTP Service",
      category: "exposed_service",
      cwe: null,
    },
    {
      pattern: /(?:بستر\s+متن\s+آشکار|cleartext|clear\s*text).*\bftp\b|\bftp\b.*(?:بستر\s+متن\s+آشکار|cleartext|clear\s*text)/,
      type: "cleartext_communication",
      name: "Cleartext Communication",
      category: "transport_security",
      cwe: "CWE-319",
    },
    {
      pattern: /host\s+header\s+injection.*plesk\s+obsidian|plesk\s+obsidian.*host\s+header\s+injection|host\s+header\s+injection/,
      type: "host_header_injection",
      name: "Host Header Injection",
      category: "web_vulnerability",
      cwe: null,
    },

    // Families introduced in v5.
    {
      pattern: /(?:دسترسی\s+بدون\s+احراز\s+هویت|unauthenticated).*redis|redis.*(?:بدون\s+احراز\s+هویت|پیکربندی\s+نامناسب|6379|6380)/,
      type: "unauthenticated_redis",
      name: "Unauthenticated Redis",
      category: "exposed_service",
      cwe: null,
    },
    {
      pattern: /(?:سرویس\s+پرخطر|سرویس\s+آسیب\s*پذیر|عدم\s+مدیریت).*rpc|\brpc\b.*(?:در\s+معرض\s+اینترنت|exposed|پرخطر)/,
      type: "exposed_rpc",
      name: "Exposed RPC Service",
      category: "exposed_service",
      cwe: null,
    },
    {
      pattern: /دسترسی\s+(?:نامجاز\s+و\s+)?بدون\s+احراز\s+هویت|unauthenticated\s+(?:file\s+)?access/,
      type: "unauthenticated_file_access",
      name: "Unauthenticated File Access",
      category: "access_control",
      cwe: null,
    },
    {
      pattern: /slow\s*http\s*(?:dos|denial\s+of\s+service)|آسیب\s*پذیری\s+slow\s*http/,
      type: "slow_http_dos",
      name: "Slow HTTP DoS",
      category: "denial_of_service",
      cwe: null,
    },
    {
      pattern: /udp\s*flood(?:ing)?|منع\s+سرویس\s*udp\s*flood/,
      type: "udp_flood",
      name: "UDP Flood",
      category: "denial_of_service",
      cwe: null,
    },
    {
      pattern: /\bdefacement\b|دیفیس/,
      type: "defacement",
      name: "Website Defacement",
      category: "web_intrusion",
      cwe: null,
    },
    {
      pattern: /(?:سرویس|پروتکل).*ntlm|ntlm.*(?:آسیب\s*پذیر|vulnerable|احراز\s+هویت)/,
      type: "vulnerable_ntlm",
      name: "Vulnerable NTLM",
      category: "authentication_protocol",
      cwe: null,
    },
    {
      pattern: /apache\s+log4j2?|log4shell|cve-2021-44228|cve-2021-45046/,
      type: "vulnerable_log4j2",
      name: "Vulnerable Apache Log4j2 / Log4Shell",
      category: "vulnerable_software",
      cwe: null,
    },
  ];

  return catalog.find((item) => item.pattern.test(text)) || {
    type: "unknown",
    name: null,
    category: "unknown",
    cwe: null,
  };
}

function vulnerabilityFromFindingV6(finding) {
  const vulnerabilityLike = new Set([
    "password_policy_violation",
    "open_dns_resolver",
    "vulnerable_wordpress",
    "vulnerable_xampp",
    "unrestricted_file_upload",
    "exposed_remote_desktop",
    "default_credentials",
    "vulnerable_rompager",
    "vulnerable_liferay",
    "hikvision_access_control_bypass",
    "vulnerable_nextjs",
    "cleartext_communication",
    "exposed_upnp_service",
    "vulnerable_cisco_asa_ftd",
    "vulnerable_zimbra",
    "dns_zone_transfer_exposure",
    "insecure_tftp_service",
    "host_header_injection",
    "unauthenticated_file_access",
    "slow_http_dos",
    "vulnerable_ntlm",
    "unauthenticated_redis",
    "exposed_rpc",
    "vulnerable_log4j2",
  ]);

  if (!finding || !vulnerabilityLike.has(finding.type)) {
    return { name: null, normalizedName: "unknown", category: "unknown", cwe: null };
  }

  return {
    name: finding.name,
    normalizedName: finding.type,
    category: finding.category,
    cwe: finding.cwe || null,
  };
}

function normalize(value) {
  return String(value || "")
    .replace(/ي/g, "ی")
    .replace(/ك/g, "ک")
    .replace(/[‌\u200c\u200f\u202a-\u202e]/g, " ")
    .replace(/[\u064b-\u065f\u0670]/g, "")
    .replace(/آسیب[\s-]*پذیری/g, "آسیب پذیری")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

module.exports = {
  STAGE_VERSION,
  enhanceReportRecordV6,
  classifyFindingV6,
  vulnerabilityFromFindingV6,
};
