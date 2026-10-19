// Shared port-risk classification. ports.ts (base TCP-connect suite) and
// networkExposure.ts (extended naabu+nmap discovery) both need "how dangerous
// is an open port, and why" — this is the single table they share so a port's
// risk reads the same whichever tool found it.

export type PortRisk = {
  port: number;
  service: string;
  risk: "critical" | "high" | "medium" | "info";
  reason: string;
};

export const PORT_TARGETS: PortRisk[] = [
  { port: 21, service: "FTP", risk: "high", reason: "Unencrypted file transfer — credentials sent in cleartext" },
  { port: 22, service: "SSH", risk: "info", reason: "Remote access — verify key-only auth is enforced, password auth disabled" },
  { port: 23, service: "Telnet", risk: "critical", reason: "Cleartext remote access — no encryption, replace with SSH immediately" },
  { port: 25, service: "SMTP", risk: "medium", reason: "Mail relay — verify not an open relay; should only accept authenticated senders" },
  { port: 53, service: "DNS", risk: "info", reason: "DNS — check zone transfer is disabled (AXFR should be restricted)" },
  { port: 80, service: "HTTP", risk: "info", reason: "Plaintext web — verify it redirects to HTTPS" },
  { port: 110, service: "POP3", risk: "medium", reason: "Unencrypted email retrieval — prefer POP3S (995)" },
  { port: 143, service: "IMAP", risk: "medium", reason: "Unencrypted email — prefer IMAPS (993)" },
  { port: 443, service: "HTTPS", risk: "info", reason: "Secure web — expected" },
  { port: 445, service: "SMB", risk: "critical", reason: "Windows file sharing — high ransomware/EternalBlue attack surface; restrict to internal network" },
  { port: 993, service: "IMAPS", risk: "info", reason: "Encrypted IMAP — expected if email is hosted here" },
  { port: 995, service: "POP3S", risk: "info", reason: "Encrypted POP3 — expected if email is hosted here" },
  { port: 1433, service: "MSSQL", risk: "high", reason: "SQL Server should not be directly internet-facing; restrict to private network" },
  { port: 1521, service: "Oracle DB", risk: "high", reason: "Oracle database should not be internet-facing" },
  { port: 2375, service: "Docker API (plain)", risk: "critical", reason: "Unauthenticated Docker daemon — full container escape / host takeover" },
  { port: 2376, service: "Docker API (TLS)", risk: "high", reason: "Docker daemon exposed; ensure client cert auth is enforced" },
  { port: 2379, service: "etcd", risk: "critical", reason: "Kubernetes etcd — full cluster secrets readable without auth" },
  { port: 3000, service: "Dev server", risk: "medium", reason: "Development server exposed to internet — likely unintentional" },
  { port: 3306, service: "MySQL/MariaDB", risk: "high", reason: "Database should not be directly internet-facing" },
  { port: 3389, service: "RDP", risk: "high", reason: "Remote Desktop — high-value brute-force / BlueKeep target; restrict to VPN" },
  { port: 4444, service: "Metasploit default", risk: "critical", reason: "Default Metasploit listener port — should never be open in production" },
  { port: 5432, service: "PostgreSQL", risk: "high", reason: "Database should not be directly internet-facing" },
  { port: 5900, service: "VNC", risk: "critical", reason: "Graphical remote access with weak default auth — restrict or disable" },
  { port: 6379, service: "Redis", risk: "critical", reason: "Redis is often unauthenticated by default — full data read/write, RCE via config set" },
  { port: 8080, service: "HTTP alt", risk: "medium", reason: "Alt HTTP port — may be a dev or admin interface; verify intent" },
  { port: 8443, service: "HTTPS alt", risk: "medium", reason: "Alt HTTPS port — may be an admin panel; verify intent" },
  { port: 8888, service: "Jupyter Notebook", risk: "critical", reason: "Jupyter often has no auth; grants full Python execution and filesystem access" },
  { port: 9200, service: "Elasticsearch", risk: "critical", reason: "Elasticsearch is often unauthenticated — full index read/write; data breach risk" },
  { port: 9300, service: "Elasticsearch cluster", risk: "high", reason: "Elasticsearch inter-node port exposed — restrict to cluster network" },
  { port: 27017, service: "MongoDB", risk: "critical", reason: "MongoDB is often unauthenticated by default — full DB access" },
];

/** Port → its risk classification, for a direct lookup by port number. */
export const PORT_RISK: Record<number, PortRisk> = Object.fromEntries(PORT_TARGETS.map((t) => [t.port, t]));
