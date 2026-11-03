#!/usr/bin/env bash
# Installs the extended scan tool suite. The one place the tool versions and
# SHA-256 pins live: the scan-worker image (Dockerfile's `scan-worker` stage,
# run by the Azure Container Apps Job in azure/terraform/scan-workers.tf) and
# the GitHub Actions fallback (.github/workflows/scheduled-scans.yml) both run
# this script, so the two worker paths can't drift onto different binaries.
# tool-integration.yml still installs its own copy to run the real-binary
# tests; scanTools.test.ts fails if its pins differ from these.
#
# Usage: scan-tools.sh <system|user|verify|all> <app-dir>
#   system  apt packages and binaries under /usr/local/bin and /opt (as root,
#           or through sudo on a GitHub runner)
#   user    per-user installs that must belong to the account that scans:
#           sqlmap/zizmor/arjun on ~/.local/bin, whatwaf (writes ~/.whatwaf
#           and refuses to install as root), nuclei templates, trivy's DB
#   verify  fails unless every tool answers on PATH
#   all     system, then user (the GitHub runner, where one user does both)
#
# Two failure modes. SCAN_TOOLS_STRICT=1 (the image) makes every install fail
# the build, so an image can never ship missing a tool (CLAUDE.md rule 15: an
# install that only logs a failure hides a tool that never installed). Without
# it (the Actions fallback) the steps that were fail-soft in the workflow stay
# fail-soft — the wrapper in src/worker/tools/ then reports not_configured for
# that one check — and the ones that were hard (apt, dalfox, nuclei, gospider,
# kiterunner) still fail the job.
#
# Each section keeps the reasoning the workflow step it came from carried.
set -euo pipefail

MODE="${1:-all}"
APP_DIR="$(cd "${2:-.}" && pwd)"
STRICT="${SCAN_TOOLS_STRICT:-0}"

SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi

# --- Pins --------------------------------------------------------------------
# Release binaries: version AND SHA-256 (publisher checksums file where one
# exists, otherwise the digest of the asset we verified — noted per tool).
DALFOX_VERSION=3.2.4
DALFOX_SHA256=aaef3f3d26d2de6d4e61ef5295151d9de36e111981618136ac7ec54b578582b8
NUCLEI_VERSION=v3.11.1
NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
NUCLEI_TEMPLATES_VERSION=v10.5.1
SUBFINDER_VERSION=v2.17.0
SUBFINDER_SHA256=a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37
HTTPX_VERSION=v1.12.0
HTTPX_SHA256=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
KATANA_VERSION=v1.8.0
KATANA_SHA256=cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2
NAABU_VERSION=v2.6.1
NAABU_SHA256=018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90
FFUF_VERSION=2.3.0
FFUF_SHA256=b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb
GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
TRIVY_VERSION=0.76.0
TRIVY_SHA256=e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7
OPENGREP_VERSION=1.31.0
OPENGREP_SHA256=dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147
GOSPIDER_VERSION=1.1.6
GOSPIDER_SHA256=41bdd76aff8d063655dc473f035ca7659f8549fbf264be5185f50d288666f93d
KITERUNNER_VERSION=1.0.2
KITERUNNER_SHA256=6f0b70aabf747de592445a690281897eebbc45927e9264185d34ffb11637613b
# A PyPI wheel, downloaded from PyPI's file host and checked like a binary.
PROWLER_VERSION=5.47.0
PROWLER_SHA256=8921b03330bc17182d7ed7260afe285bb6096829cacb14a74baa9d6914aef5b6
# Git checkouts: a release tag or commit, never a default branch's HEAD — the
# worker holds the Supabase service-role key, so what it runs must not change
# whenever upstream pushes.
COMMIX_TAG=v4.1
TESTSSL_TAG=v3.2.4
WHATWAF_TAG=v1.9
CMSMAP_COMMIT=59dd0e2b3b0c751c6da2b0565374ab83c736b0e6
# Package indexes: pip checks the files against PyPI's hashes for the exact
# pinned release, the equivalent guarantee of a SHA-256 check on a binary.
SQLMAP_VERSION=1.10.10
ZIZMOR_VERSION=1.31.1
BADSECRETS_VERSION=1.2.0
ARJUN_VERSION=2.2.7
# 3.8.28 is the newest wpscan that runs on Ruby 3.2 (ubuntu-latest) and 3.1
# (Debian bookworm, the image): every 4.x release needs Ruby >= 3.3.
WPSCAN_VERSION=3.8.28

FAILED=()

# step <hard|soft> <name> <function>: runs one install. A soft step that fails
# is recorded and reported, and only fails the run in strict mode.
step() {
  local kind="$1" name="$2" fn="$3" rc
  echo "::group::${name}"
  # Not `if ( ... )`: bash ignores set -e inside a command used as a
  # condition, so a failed download midway through would carry on silently.
  set +e
  ( set -euo pipefail; "$fn" )
  rc=$?
  set -e
  echo "::endgroup::"
  if [ "$rc" = "0" ]; then return 0; fi
  if [ "$kind" = "hard" ] || [ "$STRICT" = "1" ]; then
    echo "::error::${name} failed to install"
    exit 1
  fi
  echo "::warning::${name} failed to install — its check will report status: not_configured"
  FAILED+=("$name")
}

# fetch <url> <sha256> <dest>: download and verify, removing the file on a
# mismatch so nothing unverified is ever unpacked.
fetch() {
  curl -fsSL "$1" -o "$3"
  if ! echo "$2  $3" | sha256sum -c -; then
    rm -f "$3"
    return 1
  fi
}

# --- system ------------------------------------------------------------------

install_apt() {
  $SUDO apt-get update
  # hydra backs the Tier A offensive `credentialSpray` tool; it only runs
  # under the offensive profile and only when the owner has configured a
  # designated test account + wordlist + form spec, so installing it does not
  # by itself spray anything. libpcap lets naabu use its privileged path; it
  # falls back to an unprivileged connect scan without raw sockets. ruby-dev
  # and build-essential build wpscan's native gems; bsdextrautils (hexdump),
  # dnsutils and procps are testssl.sh's runtime dependencies.
  $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nmap hydra python3 python3-pip python3-venv git curl ca-certificates unzip openssl \
    libpcap-dev ruby ruby-dev build-essential zlib1g-dev libcurl4-openssl-dev \
    bsdextrautils dnsutils procps
}

install_commix() {
  # No official PyPI release; normally run from a git checkout (see the
  # CONFIDENCE NOTE in src/worker/tools/commix.ts). (xsser was retired: not
  # installable on the runner image, and ZAP already covers XSS.)
  $SUDO rm -rf /opt/commix
  $SUDO git clone --depth 1 --branch "$COMMIX_TAG" https://github.com/commixproject/commix.git /opt/commix
  $SUDO ln -sf /opt/commix/commix.py /usr/local/bin/commix
  $SUDO chmod +x /opt/commix/commix.py
}

install_dalfox() {
  # dalfox publishes no checksums.txt covering per-platform binaries; the hash
  # is the real asset digest from the GitHub release (2026-10-23). dalfox.ts
  # parses its real v3.2.4 `-f json` output (fixtures/dalfox/).
  fetch "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-x86_64.tar.gz" \
    "$DALFOX_SHA256" /tmp/dalfox.tar.gz
  tar -xzf /tmp/dalfox.tar.gz -C /tmp
  $SUDO install "/tmp/dalfox-v${DALFOX_VERSION}-linux-x86_64/dalfox" /usr/local/bin/dalfox
  rm -rf /tmp/dalfox.tar.gz "/tmp/dalfox-v${DALFOX_VERSION}-linux-x86_64"
  dalfox --version
}

# ProjectDiscovery release zips share one shape: <tool>_<version>_linux_amd64.zip
# holding a single binary. SHA-256s are the publisher's own checksums lines,
# cross-checked against the downloaded asset.
install_pd_zip() {
  local tool="$1" version="$2" sha="$3"
  fetch "https://github.com/projectdiscovery/${tool}/releases/download/${version}/${tool}_${version#v}_linux_amd64.zip" \
    "$sha" "/tmp/${tool}.zip"
  $SUDO unzip -o "/tmp/${tool}.zip" "$tool" -d /usr/local/bin
  $SUDO chmod +x "/usr/local/bin/${tool}"
  rm -f "/tmp/${tool}.zip"
}

install_nuclei() { install_pd_zip nuclei "$NUCLEI_VERSION" "$NUCLEI_SHA256" && nuclei -version; }
# subdomains.ts shells out to subfinder; before 2026-09-30 it was never
# installed, so subdomain discovery was always not_configured.
install_subfinder() { install_pd_zip subfinder "$SUBFINDER_VERSION" "$SUBFINDER_SHA256" && subfinder -version; }
# hostProbe.ts probes the hosts subfinder found for a live HTTP service.
install_httpx() { install_pd_zip httpx "$HTTPX_VERSION" "$HTTPX_SHA256" && httpx -version; }
# katana.ts: JavaScript-aware page discovery feeding the crawler's page checks.
install_katana() { install_pd_zip katana "$KATANA_VERSION" "$KATANA_SHA256" && katana -version; }
# networkExposure.ts: naabu top-1000 discovery, then nmap -sV on what's open.
install_naabu() { install_pd_zip naabu "$NAABU_VERSION" "$NAABU_SHA256" && naabu -version; }

install_ffuf() {
  # Tier A offensive content discovery (contentDiscovery.ts) only — runs under
  # the `offensive` profile with a per-scan authorization, never otherwise.
  fetch "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
    "$FFUF_SHA256" /tmp/ffuf.tar.gz
  $SUDO tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf
  $SUDO chmod +x /usr/local/bin/ffuf
  rm -f /tmp/ffuf.tar.gz
  ffuf -V
}

install_gitleaks() {
  # secretScan.ts. Was never installed until the workflow step this came from.
  fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    "$GITLEAKS_SHA256" /tmp/gitleaks.tar.gz
  $SUDO tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks
  $SUDO chmod +x /usr/local/bin/gitleaks
  rm -f /tmp/gitleaks.tar.gz
  gitleaks version
}

install_testssl() {
  # A shell script with no compiled release: cloned and pointed to through
  # TESTSSL_PATH (deepTls.ts reads it, else a bare "testssl.sh" on PATH).
  $SUDO rm -rf /opt/testssl.sh
  $SUDO git clone --depth 1 --branch "$TESTSSL_TAG" https://github.com/testssl/testssl.sh.git /opt/testssl.sh
  test -x /opt/testssl.sh/testssl.sh
}

install_trivy() {
  # trivyScan.ts. The previous pin (0.58.1) had no release assets, so trivy
  # silently never installed. 0.75.0's JSON output is checked against the
  # parser by src/worker/tools/fixtures/trivy/config-0.75.0.json.
  fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    "$TRIVY_SHA256" /tmp/trivy.tar.gz
  $SUDO tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
  rm -f /tmp/trivy.tar.gz
  trivy --version
}

install_opengrep() {
  # sast.ts with our own rule pack in sast-rules/. LGPL-2.1, run as a separate
  # binary. SHA-256 as published by GitHub's release API.
  fetch "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" \
    "$OPENGREP_SHA256" /tmp/opengrep
  $SUDO install -m 0755 /tmp/opengrep /usr/local/bin/opengrep
  rm -f /tmp/opengrep
  opengrep --version
}

install_badsecrets() {
  # AGPL-3.0, run unmodified as a separate program, in its own virtualenv so
  # its Django/yara dependencies can't clash with the other pip tools.
  $SUDO rm -rf /opt/badsecrets
  $SUDO python3 -m venv /opt/badsecrets
  $SUDO /opt/badsecrets/bin/pip install --quiet "badsecrets==${BADSECRETS_VERSION}"
  $SUDO ln -sf /opt/badsecrets/bin/badsecrets /usr/local/bin/badsecrets
  badsecrets -l --no-color | tail -3
}

install_wpscan() {
  $SUDO gem install wpscan -v "$WPSCAN_VERSION" --no-document
}

install_cmsmap() {
  # No PyPI package and no release tags: a pinned commit, whose setup.py
  # registers the `cmsmap` console script the wrapper calls.
  $SUDO rm -rf /opt/cmsmap
  $SUDO git clone https://github.com/Dionach/CMSmap.git /opt/cmsmap
  $SUDO git -C /opt/cmsmap checkout "$CMSMAP_COMMIT"
  $SUDO pip3 install --break-system-packages /opt/cmsmap
}

install_gospider() {
  # The asset is linux_x86_64 (not linux_amd64) and the binary sits inside a
  # folder in the zip. jaeles publishes no checksums file, so the SHA-256 is
  # the one we verified. gospider.ts parses its real v1.1.6 --json output.
  fetch "https://github.com/jaeles-project/gospider/releases/download/v${GOSPIDER_VERSION}/gospider_v${GOSPIDER_VERSION}_linux_x86_64.zip" \
    "$GOSPIDER_SHA256" /tmp/gospider.zip
  unzip -o /tmp/gospider.zip -d /tmp/gospider
  $SUDO install "/tmp/gospider/gospider_v${GOSPIDER_VERSION}_linux_x86_64/gospider" /usr/local/bin/gospider
  rm -rf /tmp/gospider /tmp/gospider.zip
}

install_kiterunner() {
  # v1.0.2 is the latest release (v2.0.2 never existed). No publisher
  # checksums file; the SHA-256 is the one we verified.
  fetch "https://github.com/assetnote/kiterunner/releases/download/v${KITERUNNER_VERSION}/kiterunner_${KITERUNNER_VERSION}_linux_amd64.tar.gz" \
    "$KITERUNNER_SHA256" /tmp/kiterunner.tar.gz
  $SUDO tar -xzf /tmp/kiterunner.tar.gz -C /usr/local/bin kr
  $SUDO chmod +x /usr/local/bin/kr
  rm -f /tmp/kiterunner.tar.gz
}

install_kiterunner_wordlist() {
  # Our own curated route list compiled to .kite; KITERUNNER_WORDLIST points
  # kiterunner.ts at it (it no-ops to not_configured without that variable).
  $SUDO mkdir -p /opt/kiterunner
  $SUDO kr kb convert "${APP_DIR}/src/worker/tools/wordlists/api-routes.txt" /opt/kiterunner/api-routes.kite
}

install_prowler() {
  # Read-only AWS IAM / privilege-escalation posture of customers who
  # connected a cross-account role (src/worker/tools/prowlerIam.ts).
  # Apache-2.0, in its own venv. Only the wheel is hash-checked; pip resolves
  # its dependencies at install time (see OT-47). Hard, unlike most installs:
  # prowlerIam.ts reports an error (never a clean result) for an owner with a
  # role connected, so a silent non-install would be a permanently red check.
  local wheel="/tmp/prowler-${PROWLER_VERSION}-py3-none-any.whl"
  fetch "https://files.pythonhosted.org/packages/23/fa/bf388f40a49322653af49a07d515354758f1915767448e56b1af4824ed38/prowler-${PROWLER_VERSION}-py3-none-any.whl"     "$PROWLER_SHA256" "$wheel"
  $SUDO rm -rf /opt/prowler
  $SUDO python3 -m venv /opt/prowler
  $SUDO /opt/prowler/bin/pip install --quiet "$wheel"
  $SUDO ln -sf /opt/prowler/bin/prowler /usr/local/bin/prowler
  rm -f "$wheel"
  prowler --version | grep -F "$PROWLER_VERSION"
}

# strix and cairn are deliberately not installed: the owner decision of
# 2026-10-23 leaves them not_configured and unmarketed (docs/NEXT-STEPS.md),
# and the tags the workflow once fetched never existed. Re-pin to real tags
# (strix v1.x / cairn v0.2.x) with a SHA-256 check before any future attempt.
# photon is not installed either: the PyPI package puts no `photon` on PATH.

system() {
  step hard "apt packages (nmap, hydra, python3, ruby)" install_apt
  step soft "commix ${COMMIX_TAG}" install_commix
  step hard "dalfox ${DALFOX_VERSION}" install_dalfox
  step hard "nuclei ${NUCLEI_VERSION}" install_nuclei
  step soft "subfinder ${SUBFINDER_VERSION}" install_subfinder
  step soft "httpx ${HTTPX_VERSION}" install_httpx
  step soft "katana ${KATANA_VERSION}" install_katana
  step soft "naabu ${NAABU_VERSION}" install_naabu
  step soft "ffuf ${FFUF_VERSION}" install_ffuf
  step soft "gitleaks ${GITLEAKS_VERSION}" install_gitleaks
  step soft "testssl.sh ${TESTSSL_TAG}" install_testssl
  step soft "trivy ${TRIVY_VERSION}" install_trivy
  step soft "opengrep ${OPENGREP_VERSION}" install_opengrep
  step soft "badsecrets ${BADSECRETS_VERSION}" install_badsecrets
  step soft "wpscan ${WPSCAN_VERSION}" install_wpscan
  step soft "cmsmap ${CMSMAP_COMMIT:0:7}" install_cmsmap
  step hard "gospider ${GOSPIDER_VERSION}" install_gospider
  step hard "kiterunner ${KITERUNNER_VERSION}" install_kiterunner
  step soft "kiterunner wordlist" install_kiterunner_wordlist
  step hard "prowler ${PROWLER_VERSION}" install_prowler
}

# --- user --------------------------------------------------------------------

install_sqlmap() {
  pip3 install --user --break-system-packages "sqlmap==${SQLMAP_VERSION}"
  "$HOME/.local/bin/sqlmap" --version
}

install_zizmor() {
  pip3 install --user --break-system-packages "zizmor==${ZIZMOR_VERSION}"
  "$HOME/.local/bin/zizmor" --version
}

install_arjun() {
  pip3 install --user --break-system-packages "arjun==${ARJUN_VERSION}"
}

install_whatwaf() {
  # No PyPI package. Three traps, found on a runner in tool-integration.yml:
  #   1. setup.py imports bs4 at metadata time, so install its requirements
  #      FIRST.
  #   2. setup.py prompts via raw_input when run as root, which aborts under
  #      pip's closed stdin, so install UNPRIVILEGED.
  #   3. its install_helper.sh writes ~/.whatwaf in the installing user's
  #      home, so it must be the user that scans.
  rm -rf /tmp/whatwaf
  git clone --depth 1 --branch "$WHATWAF_TAG" https://github.com/Ekultek/WhatWaf.git /tmp/whatwaf
  pip3 install --user --break-system-packages -r /tmp/whatwaf/requirements.txt
  pip3 install --user --break-system-packages /tmp/whatwaf
  rm -rf /tmp/whatwaf
  test -n "$(ls -A "$HOME/.whatwaf/plugins")"
}

install_nuclei_templates() {
  # Pinned to a release tag instead of `-update-templates`' floating latest, so
  # a scan is reproducible and a compromised templates push can't change what
  # the worker runs. nuclei loads every template in its default directory and
  # filters by -tags at scan time; only the version is fixed. Bump this with
  # the nuclei binary above, checking they are compatible.
  local dir="$HOME/nuclei-templates"
  rm -rf "$dir"
  git clone --depth 1 --branch "$NUCLEI_TEMPLATES_VERSION" https://github.com/projectdiscovery/nuclei-templates.git "$dir"
  mkdir -p "$HOME/.config/nuclei"
  printf '{"nuclei-templates-directory":"%s","nuclei-templates-version":"%s"}\n' "$dir" "$NUCLEI_TEMPLATES_VERSION" \
    > "$HOME/.config/nuclei/.templates-config.json"
  echo "nuclei templates ${NUCLEI_TEMPLATES_VERSION}: $(find "$dir" -name '*.yaml' | wc -l) templates"
}

install_trivy_db() {
  # Prime the vulnerability DB so a scan doesn't spend its own exec timeout on
  # a first-run download. trivy refreshes it itself once it is a day old.
  trivy image --download-db-only --quiet
}

user() {
  step hard "sqlmap ${SQLMAP_VERSION}" install_sqlmap
  step soft "zizmor ${ZIZMOR_VERSION}" install_zizmor
  step soft "arjun ${ARJUN_VERSION}" install_arjun
  step soft "whatwaf ${WHATWAF_TAG}" install_whatwaf
  step soft "nuclei templates ${NUCLEI_TEMPLATES_VERSION}" install_nuclei_templates
  step soft "trivy vulnerability DB" install_trivy_db
}

# --- verify ------------------------------------------------------------------

# Every command a src/worker/tools/ or src/lib/scanners/ wrapper shells out to.
TOOLS=(nmap hydra sqlmap commix dalfox nuclei subfinder httpx katana naabu ffuf gitleaks trivy
  opengrep zizmor badsecrets whatwaf wpscan cmsmap gospider kr arjun prowler)

verify() {
  local missing=()
  for tool in "${TOOLS[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  [ -x /opt/testssl.sh/testssl.sh ] || missing+=("testssl.sh")
  [ -f /opt/kiterunner/api-routes.kite ] || missing+=("kiterunner wordlist")
  [ -d "$HOME/nuclei-templates" ] || missing+=("nuclei templates")
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "::error::missing scan tools: ${missing[*]}"
    exit 1
  fi
  echo "all ${#TOOLS[@]} scan tools, testssl.sh, the kiterunner wordlist and nuclei templates are present"
}

case "$MODE" in
  system) system ;;
  user) user ;;
  verify) verify ;;
  all) system; user ;;
  *) echo "usage: $0 <system|user|verify|all> <app-dir>" >&2; exit 2 ;;
esac

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "::warning::not installed (fail-soft): ${FAILED[*]}"
fi
