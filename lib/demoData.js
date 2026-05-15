// Static demo data for the showcase site.
// Mirrors the shape returned by the real Supabase backend so the existing
// dashboard / history / scan-result components render without modification.

export const DEMO_USER = {
  id: 'demo-user-0001',
  email: 'demo@aegir.live',
  full_name: 'Showcase Demo',
}

const now = Date.now()

// Curated showcase scans drawn from real test runs against loopback +
// a Metasploitable 2 lab VM. Findings, CVE IDs and AI summary text are
// copied verbatim from production scan output.

export const DEMO_SCAN_DETAIL = {
  id: 'scan-demo-metasploitable',
  user_id: DEMO_USER.id,
  target_redacted: '192.168.56.XXX',
  scan_mode: 'pen_test',
  scan_timestamp: new Date(now - 1000 * 60 * 17).toISOString(),
  ports_json: [
    { port: 21,   protocol: 'tcp', state: 'open', service: 'ftp',      product: 'vsftpd',          version: '2.3.4' },
    { port: 22,   protocol: 'tcp', state: 'open', service: 'ssh',      product: 'OpenSSH',         version: '4.7p1 Debian 8ubuntu1' },
    { port: 23,   protocol: 'tcp', state: 'open', service: 'telnet',   product: 'Linux telnetd',   version: '' },
    { port: 25,   protocol: 'tcp', state: 'open', service: 'smtp',     product: 'Postfix smtpd',   version: '' },
    { port: 80,   protocol: 'tcp', state: 'open', service: 'http',     product: 'Apache httpd',    version: '2.2.8' },
    { port: 139,  protocol: 'tcp', state: 'open', service: 'netbios-ssn', product: 'Samba smbd',   version: '3.X - 4.X' },
    { port: 445,  protocol: 'tcp', state: 'open', service: 'netbios-ssn', product: 'Samba smbd',   version: '3.0.20-Debian' },
    { port: 3306, protocol: 'tcp', state: 'open', service: 'mysql',    product: 'MySQL',           version: '5.0.51a-3ubuntu5' },
    { port: 5432, protocol: 'tcp', state: 'open', service: 'postgresql', product: 'PostgreSQL DB', version: '8.3.0 - 8.3.7' },
    { port: 5900, protocol: 'tcp', state: 'open', service: 'vnc',      product: 'VNC',             version: 'protocol 3.3' },
  ],
  cve_findings_json: [
    { cve_id: 'CVE-2011-2523', cvss: 10.0, severity: 'critical', product: 'vsftpd 2.3.4', summary: 'vsftpd 2.3.4 backdoor — connecting users with `:)` in username receive a root shell on TCP/6200.' },
    { cve_id: 'CVE-2008-0166', cvss: 9.8,  severity: 'critical', product: 'OpenSSH 4.7p1', summary: 'Debian/Ubuntu OpenSSL PRNG weakness — SSH keys generated in this period are trivially brute-forceable.' },
    { cve_id: 'CVE-2007-2447', cvss: 9.8,  severity: 'critical', product: 'Samba 3.0.20', summary: 'Username map script RCE in Samba — unauthenticated command injection via crafted username.' },
    { cve_id: 'CVE-2017-7494', cvss: 9.8,  severity: 'critical', product: 'Samba smbd',   summary: 'SambaCry — remote code execution via shared library upload to a writable share.' },
    { cve_id: 'CVE-2010-0425', cvss: 8.1,  severity: 'high',     product: 'Apache 2.2.8', summary: 'Apache mod_isapi use-after-free — remote DoS / potential RCE via crafted ISAPI request.' },
    { cve_id: 'CVE-2009-2412', cvss: 7.5,  severity: 'high',     product: 'Apache 2.2.8', summary: 'Apache integer overflow in apr — heap corruption via large input lengths.' },
    { cve_id: 'CVE-2012-2122', cvss: 7.5,  severity: 'high',     product: 'MySQL 5.0.51', summary: 'MySQL authentication bypass — repeated login attempts succeed with random memcmp truncation.' },
    { cve_id: 'CVE-2007-4752', cvss: 5.3,  severity: 'medium',   product: 'OpenSSH 4.7',  summary: 'OpenSSH X11 cookie spoofing — local users can hijack X11 forwarding sessions.' },
  ],
  cve_count: 8,
  highest_cvss: 10.0,
  crit_count: 4,
  high_count: 3,
  med_count: 1,
  low_count: 0,
  firewall_json: { state: 'no_firewall', method: 'scapy_ack_probe', confidence: 'high' },
  traffic_json: { capture_duration_s: 30, packets_observed: 412, top_talkers: 2 },
  ai_summary: `## Executive Summary

This Metasploitable 2 host exposes **10 open services** with **4 critical** and **3 high-severity** vulnerabilities, the most severe being **CVE-2011-2523 (CVSS 10.0)** — the well-documented \`vsftpd 2.3.4\` backdoor that grants unauthenticated root access via a crafted FTP login.

The combination of an exploitable Samba RCE (CVE-2017-7494), an OpenSSL PRNG flaw that compromises every SSH key generated on this build (CVE-2008-0166), and a MySQL authentication bypass (CVE-2012-2122) makes this host **trivial to fully compromise** with off-the-shelf Metasploit modules.

## Vulnerability Breakdown

**Critical — patch immediately**
- **vsftpd 2.3.4 backdoor** — replace with current vsftpd 3.x or proftpd; or remove FTP entirely
- **Samba 3.0.20 (CVE-2007-2447, CVE-2017-7494)** — upgrade to Samba ≥ 4.6.4 with \`nt pipe support = no\` set in \`smb.conf\`
- **OpenSSH 4.7 / Debian OpenSSL** — regenerate all host and user keys after upgrading openssl-blacklist

**High — schedule within 7 days**
- **Apache 2.2.8** — upgrade to Apache 2.4 LTS; mod_isapi is Windows-only but the integer overflow affects all 2.2.x
- **MySQL 5.0.51a** — upgrade to MySQL 5.7 LTS or migrate to MariaDB 10.6+; bind to localhost if remote access is not required

## Remediation Steps

1. **Take this host off the network** until the critical issues are resolved — every open service has at least one unauthenticated RCE
2. \`apt-get update && apt-get dist-upgrade\` on the underlying Ubuntu, then rebuild each service from current packages
3. Audit the Samba shares and disable any guest-writable shares; rotate all credentials that were on this host
4. Replace VNC (no auth, protocol 3.3) with SSH X11 forwarding or no remote display at all
5. Confirm Postfix / PostgreSQL bindings are loopback-only after the upgrade

## Compliance Notes

This host fails **PCI-DSS 11.2** (quarterly vulnerability scans must show no high or critical findings), **CIS Ubuntu Benchmark 5.1** (unnecessary services running), and **NIST 800-53 CM-7** (least functionality).`,
}

export const DEMO_SCANS = [
  // most recent first
  {
    id: 'scan-demo-metasploitable',
    target_redacted: '192.168.56.XXX',
    scan_timestamp: new Date(now - 1000 * 60 * 17).toISOString(),
    scan_mode: 'pen_test',
    ports_json: DEMO_SCAN_DETAIL.ports_json,
    cve_count: 8,
    highest_cvss: 10.0,
    crit_count: 4,
    high_count: 3,
    med_count: 1,
    low_count: 0,
  },
  {
    id: 'scan-demo-loopback',
    target_redacted: '127.0.0.X',
    scan_timestamp: new Date(now - 1000 * 60 * 60 * 3).toISOString(),
    scan_mode: 'fast',
    ports_json: [
      { port: 22, protocol: 'tcp', state: 'open', service: 'ssh', product: 'OpenSSH', version: '8.9p1 Ubuntu 3ubuntu0.7' },
    ],
    cve_count: 2,
    highest_cvss: 6.5,
    crit_count: 0,
    high_count: 0,
    med_count: 2,
    low_count: 0,
  },
  {
    id: 'scan-demo-homelab',
    target_redacted: '10.0.0.XXX',
    scan_timestamp: new Date(now - 1000 * 60 * 60 * 26).toISOString(),
    scan_mode: 'deep',
    ports_json: [
      { port: 80,   protocol: 'tcp', state: 'open', service: 'http',   product: 'nginx',      version: '1.24.0' },
      { port: 443,  protocol: 'tcp', state: 'open', service: 'https',  product: 'nginx',      version: '1.24.0' },
      { port: 8080, protocol: 'tcp', state: 'open', service: 'http-proxy', product: 'Traefik', version: '2.10.4' },
    ],
    cve_count: 1,
    highest_cvss: 5.3,
    crit_count: 0,
    high_count: 0,
    med_count: 1,
    low_count: 0,
  },
  {
    id: 'scan-demo-pfsense',
    target_redacted: '192.168.1.XXX',
    scan_timestamp: new Date(now - 1000 * 60 * 60 * 72).toISOString(),
    scan_mode: 'fast',
    ports_json: [
      { port: 53,  protocol: 'tcp', state: 'open',     service: 'dns', product: 'Unbound', version: '1.17.1' },
      { port: 443, protocol: 'tcp', state: 'open',     service: 'https', product: 'nginx', version: '1.24.0' },
      { port: 22,  protocol: 'tcp', state: 'filtered', service: 'ssh',   product: '',      version: '' },
    ],
    cve_count: 0,
    highest_cvss: 0,
    crit_count: 0,
    high_count: 0,
    med_count: 0,
    low_count: 0,
  },
]
