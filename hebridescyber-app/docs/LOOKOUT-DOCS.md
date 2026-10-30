# Lookout docs — external tool defensive reference catalogue

Unrelated to this product's own scanner pipeline (see `docs/SCANNER-INVENTORY.md`
for tools hebridescyber-app actually runs). This is a standalone reference
catalogue of general-purpose software items drawn from the public
[`enaqx/awesome-pentest`](https://github.com/enaqx/awesome-pentest) list —
anonymity tools, collaboration/reporting platforms, file-format analysis
tools, and hex editors. Each entry gives a neutral description plus
indicative defensive-monitoring context (observable behaviour, likely
telemetry sources, high-level MITRE ATT&CK associations). It contains no
operational, exploitation, or evasion guidance.

```json
[
  {
    "name": "Metadata Anonymization Toolkit (MAT2)",
    "category": "Anonymity Tools",
    "description": "A utility that strips embedded metadata (author names, GPS coordinates, software versions, timestamps) from common document, image, and media file formats.",
    "defensive_category": "Information Hygiene / Anti-Forensics",
    "observable_behaviour": "Local file read/rewrite operations that alter file headers and embedded metadata fields; no network activity expected.",
    "telemetry_sources": "Endpoint file-integrity monitoring, EDR file-write/modify events, host-based audit logs.",
    "attack_mapping": ["T1070 Indicator Removal (indicative)"],
    "classification": "analysis-utility"
  },
  {
    "name": "What Every Browser Knows About You (WebKay)",
    "category": "Anonymity Tools",
    "description": "An informational web page that displays the browser and device fingerprinting data a visited site can passively collect from a visitor.",
    "defensive_category": "Awareness / Fingerprinting Demonstration",
    "observable_behaviour": "Standard outbound HTTPS request to a single web page; client-side JavaScript execution gathering browser attributes.",
    "telemetry_sources": "Web proxy logs, DNS logs, browser telemetry.",
    "attack_mapping": ["T1592.002 Gather Victim Host Information: Software (indicative)"],
    "classification": "analysis-utility"
  },
  {
    "name": "Tails",
    "category": "Anonymity Tools / Tor Tools",
    "description": "A live operating system designed to route all network traffic through the Tor network and leave no persistent trace on the host machine.",
    "defensive_category": "Network Anonymization",
    "observable_behaviour": "Boot from removable media; all outbound traffic exhibits Tor circuit-establishment patterns rather than direct destination connections.",
    "telemetry_sources": "Network flow logs (NetFlow/Zeek), proxy/firewall logs, DHCP/host inventory discrepancies (unrecognized boot media).",
    "attack_mapping": ["T1090.003 Proxy: Multi-hop Proxy (indicative)"],
    "classification": "produces-monitorable-behaviour"
  },
  {
    "name": "Tor",
    "category": "Anonymity Tools / Tor Tools",
    "description": "A network and client software that routes traffic through a distributed series of relays to obscure the originating source.",
    "defensive_category": "Network Anonymization",
    "observable_behaviour": "Connections to known Tor entry-node address ranges; distinctive TLS handshake and traffic-timing patterns associated with onion routing.",
    "telemetry_sources": "Firewall logs, NetFlow, Zeek/Suricata signatures for Tor traffic, threat-intel IP reputation feeds.",
    "attack_mapping": ["T1090.003 Proxy: Multi-hop Proxy (indicative)"],
    "classification": "produces-monitorable-behaviour"
  },
  {
    "name": "Dradis",
    "category": "Collaboration Tools",
    "description": "A reporting and information-sharing platform used by security teams to consolidate findings across a project.",
    "defensive_category": "Case Management / Reporting",
    "observable_behaviour": "Standard self-hosted web application traffic (HTTPS requests to an internal instance); no distinct offensive signature.",
    "telemetry_sources": "Internal web server access logs, application audit logs.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "Hexway Hive",
    "category": "Collaboration Tools",
    "description": "A platform for aggregating and sharing security assessment data among team members.",
    "defensive_category": "Case Management / Reporting",
    "observable_behaviour": "Standard self-hosted web application traffic; no distinct offensive signature.",
    "telemetry_sources": "Internal web server access logs, application audit logs.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "Lair",
    "category": "Collaboration Tools",
    "description": "A team-oriented environment for organizing and sharing security engagement data.",
    "defensive_category": "Case Management / Reporting",
    "observable_behaviour": "Standard self-hosted web application traffic; no distinct offensive signature.",
    "telemetry_sources": "Internal web server access logs, application audit logs.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "Pentest Collaboration Framework (PCF)",
    "category": "Collaboration Tools",
    "description": "A cross-platform toolkit for coordinating tasks and sharing data among members of a security assessment team.",
    "defensive_category": "Case Management / Reporting",
    "observable_behaviour": "Standard self-hosted web/API application traffic; no distinct offensive signature.",
    "telemetry_sources": "Internal web server access logs, application audit logs.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "Reconmap",
    "category": "Collaboration Tools",
    "description": "An open-source platform for managing and documenting security assessment workflows and findings.",
    "defensive_category": "Case Management / Reporting",
    "observable_behaviour": "Standard self-hosted web application traffic; no distinct offensive signature.",
    "telemetry_sources": "Internal web server access logs, application audit logs.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "ExifTool",
    "category": "File Format Analysis Tools",
    "description": "A utility for reading and modifying embedded metadata across a wide range of file formats.",
    "defensive_category": "File Metadata Analysis",
    "observable_behaviour": "Local file read/write operations; may be invoked in batch over a directory of files.",
    "telemetry_sources": "EDR file-access events, endpoint process-execution logs.",
    "attack_mapping": ["T1592.002 Gather Victim Host Information: Software (indicative)"],
    "classification": "analysis-utility"
  },
  {
    "name": "Hachoir",
    "category": "File Format Analysis Tools",
    "description": "A library for parsing binary streams and extracting structural metadata from files.",
    "defensive_category": "Binary/File Structure Analysis",
    "observable_behaviour": "Local, programmatic file parsing with no inherent network activity.",
    "telemetry_sources": "EDR process and file-access events.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "Kaitai Struct",
    "category": "File Format Analysis Tools",
    "description": "A declarative language and associated IDE for describing and parsing binary file formats.",
    "defensive_category": "Binary/File Structure Analysis",
    "observable_behaviour": "Local development/analysis tool usage; no inherent network activity.",
    "telemetry_sources": "Endpoint process-execution logs.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "Veles",
    "category": "File Format Analysis Tools",
    "description": "A tool for visualizing and analyzing binary data to identify structure and patterns.",
    "defensive_category": "Binary/File Structure Analysis",
    "observable_behaviour": "Local file analysis and rendering; no inherent network activity.",
    "telemetry_sources": "Endpoint process-execution logs.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "Bless",
    "category": "Hex Editors",
    "description": "A cross-platform graphical hex editor for viewing and modifying binary file content.",
    "defensive_category": "Binary Editing",
    "observable_behaviour": "Local file read/write; may alter file hashes if files are saved after modification.",
    "telemetry_sources": "EDR file-integrity monitoring, endpoint process-execution logs.",
    "attack_mapping": ["T1027 Obfuscated Files or Information (indicative, if used to alter binaries)"],
    "classification": "analysis-utility"
  },
  {
    "name": "Frhed",
    "category": "Hex Editors",
    "description": "A binary file editor for Windows systems.",
    "defensive_category": "Binary Editing",
    "observable_behaviour": "Local file read/write; may alter file hashes if files are saved after modification.",
    "telemetry_sources": "EDR file-integrity monitoring, endpoint process-execution logs.",
    "attack_mapping": ["T1027 Obfuscated Files or Information (indicative, if used to alter binaries)"],
    "classification": "analysis-utility"
  },
  {
    "name": "Hex Fiend",
    "category": "Hex Editors",
    "description": "A fast hex editor for macOS with support for comparing binary files.",
    "defensive_category": "Binary Editing",
    "observable_behaviour": "Local file read/write; may alter file hashes if files are saved after modification.",
    "telemetry_sources": "EDR file-integrity monitoring, endpoint process-execution logs.",
    "attack_mapping": ["T1027 Obfuscated Files or Information (indicative, if used to alter binaries)"],
    "classification": "analysis-utility"
  },
  {
    "name": "HexEdit.js",
    "category": "Hex Editors",
    "description": "A browser-based hex editor for inspecting and editing binary content.",
    "defensive_category": "Binary Editing",
    "observable_behaviour": "Client-side web application execution; local file access is limited to files explicitly opened in-browser.",
    "telemetry_sources": "Web proxy logs, browser telemetry.",
    "attack_mapping": [],
    "classification": "analysis-utility"
  },
  {
    "name": "Hexinator",
    "category": "Hex Editors",
    "description": "A commercial hex editor for viewing and modifying binary file content.",
    "defensive_category": "Binary Editing",
    "observable_behaviour": "Local file read/write; may alter file hashes if files are saved after modification.",
    "telemetry_sources": "EDR file-integrity monitoring, endpoint process-execution logs.",
    "attack_mapping": ["T1027 Obfuscated Files or Information (indicative, if used to alter binaries)"],
    "classification": "analysis-utility"
  },
  {
    "name": "hexedit",
    "category": "Hex Editors",
    "description": "A console-based hex editor for Unix-like systems.",
    "defensive_category": "Binary Editing",
    "observable_behaviour": "Local file read/write from a terminal session; may alter file hashes if files are saved after modification.",
    "telemetry_sources": "EDR file-integrity monitoring, shell/command history logging, endpoint process-execution logs.",
    "attack_mapping": ["T1027 Obfuscated Files or Information (indicative, if used to alter binaries)"],
    "classification": "analysis-utility"
  },
  {
    "name": "wxHexEditor",
    "category": "Hex Editors",
    "description": "A graphical hex editor available across multiple desktop platforms.",
    "defensive_category": "Binary Editing",
    "observable_behaviour": "Local file read/write; may alter file hashes if files are saved after modification.",
    "telemetry_sources": "EDR file-integrity monitoring, endpoint process-execution logs.",
    "attack_mapping": ["T1027 Obfuscated Files or Information (indicative, if used to alter binaries)"],
    "classification": "analysis-utility"
  }
]
```
