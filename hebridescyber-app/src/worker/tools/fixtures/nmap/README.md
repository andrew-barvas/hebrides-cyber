# nmap fixtures

`banner-services.xml` is the real output of `nmap -sV --open -p <ports> -oX -
127.0.0.1` — exactly the arguments `networkExposure.ts` passes — run against
the loopback banner listeners in `tests/fixtures/nmap-banners/bannerServices.ts`.
Nothing outside the machine is contacted, and no vulnerable software is
installed: each listener only presents a real product's greeting, which is
all nmap's `-sV` reads.

| Listener | Banner | nmap identifies | CPE nmap emits |
|---|---|---|---|
| `openssh-7.4` | `SSH-2.0-OpenSSH_7.4` | OpenSSH 7.4 | `cpe:/a:openbsd:openssh:7.4` |
| `openssh-8.9p1-ubuntu` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 | `cpe:/a:openbsd:openssh:8.9p1`, `cpe:/o:canonical:ubuntu_linux` |
| `vsftpd-2.3.4` | `220 (vsFTPd 2.3.4)` | vsftpd 2.3.4 | `cpe:/a:vsftpd:vsftpd:2.3.4` |
| `apache-2.4.49` | `Server: Apache/2.4.49 (Unix)` | Apache httpd 2.4.49 | `cpe:/a:apache:http_server:2.4.49` |
| `apache-no-version` | `Server: Apache` | Apache httpd, no version | `cpe:/a:apache:http_server` |

It covers each path through `serviceCve.ts`: a range match, a distribution
package (reported at `info`), an exact-version match, a product whose NVD
vendor differs from nmap's (`vsftpd` vs `vsftpd_project`), and a banner with
no version ("version unknown", never a CVE).

To re-record, with nmap installed:

```bash
npx tsx tests/fixtures/nmap-banners/capture.ts
```

The tool-integration CI job runs the same scan with the real binary
(`nmap.integration.test.ts`) and prints the XML base64-encoded after
`NMAP_BANNER_XML_BASE64`, so a refresh can also be taken from its log.
