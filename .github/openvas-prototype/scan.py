# gvm-script for the OpenVAS prototype (openvas-prototype.yml, OT-36).
#
# Run inside the gvm-tools container against gvmd's unix socket:
#   gvm-script --gmp-username admin --gmp-password ... socket /prototype/scan.py
#
# 1. Waits until gvmd has loaded the VT feed and the "Full and fast" config.
# 2. Clones that config with the "Denial of Service" and "Brute force attacks"
#    families removed, sets safe_checks=yes, and reads both back: the job fails
#    if the read-back does not match, so the safe-check configuration is
#    tested rather than assumed.
# 3. Scans the fixture app on 127.0.0.1:8099 (one TCP port, host treated as
#    alive) and waits for the report.
# 4. Writes timings and result counts to /out/result.json for the job summary.
#
# Uses raw GMP XML through send_command so it does not depend on which
# python-gvm request helpers the pinned gvm-tools image ships. send_command
# returns the raw response string in that image (the first run treated it as
# an element, so every str.find "succeeded"), hence cmd() below.

import base64
import json
import sys
import time

from lxml import etree

FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
OPENVAS_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"
EXCLUDED_FAMILIES = {"Denial of Service", "Brute force attacks"}
TARGET_HOST = "127.0.0.1"
TARGET_PORTS = "T:8099"

FEED_TIMEOUT_S = 75 * 60
SCAN_TIMEOUT_S = 45 * 60
POLL_S = 20

OUT = "/out/result.json"
result = {"started_at": time.time()}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def save():
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)


def cmd(gmp, xml):
    """Send raw GMP, parse the reply and raise unless its status is 2xx."""
    resp = gmp.send_command(xml)
    el = resp if hasattr(resp, "tag") else etree.fromstring(resp.encode())
    if not str(el.get("status", "")).startswith("2"):
        raise RuntimeError(f"{el.tag} {el.get('status')}: {el.get('status_text')}")
    return el


def text(el, path, default=""):
    found = el.find(path)
    return found.text if found is not None and found.text is not None else default


def nvt_count(gmp):
    families = cmd(gmp, "<get_nvt_families/>")
    return sum(int(text(f, "max_nvt_count", "0") or 0) for f in families.iter("family"))


def wait_for_feed(gmp):
    """VTs loaded into gvmd, count stable for three polls, Full and fast present."""
    deadline = time.time() + FEED_TIMEOUT_S
    last, stable = -1, 0
    while time.time() < deadline:
        try:
            count = nvt_count(gmp)
        except Exception as exc:  # gvmd still starting or busy
            log(f"get_nvt_families failed: {exc}")
            count = 0
        try:
            cmd(gmp, f'<get_configs config_id="{FULL_AND_FAST}"/>')
            has_config = True
        except Exception:
            has_config = False
        log(f"NVTs loaded: {count}; Full and fast present: {has_config}")
        stable = stable + 1 if count > 0 and count == last else 0
        last = count
        if has_config and stable >= 3:
            result["nvt_count"] = count
            return
        time.sleep(POLL_S)
    raise SystemExit("feed did not finish loading in time")


def wait_for_scanner(gmp):
    deadline = time.time() + 15 * 60
    while time.time() < deadline:
        try:
            resp = cmd(gmp, f'<verify_scanner scanner_id="{OPENVAS_SCANNER}"/>')
            result["scanner_version"] = text(resp, "version")
            log(f"scanner verified: {result['scanner_version']}")
            return
        except Exception as exc:
            log(f"scanner not ready: {exc}")
            time.sleep(POLL_S)
    raise SystemExit("scanner never verified")


def safe_config(gmp):
    families = cmd(gmp, "<get_nvt_families/>")
    names = [text(f, "name") for f in families.iter("family")]
    names = [n for n in names if n]
    missing = EXCLUDED_FAMILIES - set(names)
    if missing:
        log(f"warning: excluded families not in feed: {sorted(missing)}")

    created = cmd(
        gmp,
        f"<create_config><copy>{FULL_AND_FAST}</copy>"
        "<name>Prototype safe (no DoS, no brute force)</name></create_config>"
    )
    config_id = created.get("id")

    selection = "".join(
        f"<family><name>{n}</name><all>1</all><growing>1</growing></family>"
        for n in names
        if n not in EXCLUDED_FAMILIES
    )
    cmd(
        gmp,
        f'<modify_config config_id="{config_id}"><family_selection>'
        f"<growing>0</growing>{selection}</family_selection></modify_config>"
    )
    yes = base64.b64encode(b"yes").decode()
    cmd(
        gmp,
        f'<modify_config config_id="{config_id}"><preference>'
        f"<name>scanner:scanner:scanner:safe_checks</name><value>{yes}</value>"
        "</preference></modify_config>"
    )

    # Read back: the excluded families must be absent and safe_checks must be yes.
    got = cmd(
        gmp,
        f'<get_configs config_id="{config_id}" details="1" preferences="1" families="1"/>'
    )
    cfg = got.find("config")
    enabled = {text(f, "name") for f in cfg.iter("family") if text(f, "name")}
    leaked = EXCLUDED_FAMILIES & enabled
    # Scanner preferences are the ones not attached to an NVT (empty oid).
    safe = None
    for pref in cfg.iter("preference"):
        nvt = pref.find("nvt")
        if text(pref, "name") == "safe_checks" and (nvt is None or not nvt.get("oid")):
            safe = text(pref, "value")
    result["config"] = {
        "families_enabled": len(enabled),
        "families_excluded": sorted(EXCLUDED_FAMILIES),
        "safe_checks": safe,
        "nvts_selected": int(text(cfg, "nvt_count", "0") or 0),
    }
    log(f"safe config: {result['config']}")
    if leaked:
        raise SystemExit(f"excluded families still enabled: {sorted(leaked)}")
    if safe != "yes":
        raise SystemExit(f"safe_checks read back as {safe!r}, not 'yes'")
    return config_id


def run_scan(gmp, config_id):
    ports = cmd(
        gmp,
        f"<create_port_list><name>fixture</name><port_range>{TARGET_PORTS}</port_range>"
        "</create_port_list>"
    ).get("id")
    target = cmd(
        gmp,
        f"<create_target><name>fixture</name><hosts>{TARGET_HOST}</hosts>"
        f'<port_list id="{ports}"/><alive_tests>Consider Alive</alive_tests>'
        "</create_target>"
    ).get("id")
    task = cmd(
        gmp,
        "<create_task><name>fixture scan</name>"
        f'<config id="{config_id}"/><target id="{target}"/>'
        f'<scanner id="{OPENVAS_SCANNER}"/></create_task>'
    ).get("id")
    started = time.time()
    report_id = text(cmd(gmp, f'<start_task task_id="{task}"/>'), "report_id")
    result["scan_started_at"] = started

    deadline = started + SCAN_TIMEOUT_S
    status = ""
    while time.time() < deadline:
        t = cmd(gmp, f'<get_tasks task_id="{task}"/>').find("task")
        status, progress = text(t, "status"), text(t, "progress")
        log(f"scan status: {status} ({progress}%)")
        if status in ("Done", "Stopped", "Interrupted"):
            break
        time.sleep(POLL_S)
    result["scan_status"] = status
    result["scan_seconds"] = round(time.time() - started)

    results = cmd(
        gmp,
        f'<get_results filter="report_id={report_id} rows=-1 min_qod=0 apply_overrides=0"/>'
    )
    rows = [r for r in results.findall("result")]
    by_severity = {"high": 0, "medium": 0, "low": 0, "log": 0}
    families = {}
    titles = []
    for r in rows:
        sev = float(text(r, "severity", "0") or 0)
        bucket = "high" if sev >= 7 else "medium" if sev >= 4 else "low" if sev > 0 else "log"
        by_severity[bucket] += 1
        fam = text(r, "nvt/family", "?")
        families[fam] = families.get(fam, 0) + 1
        titles.append(f"{sev:.1f} {text(r, 'name')}")
    result["result_count"] = len(rows)
    result["by_severity"] = by_severity
    result["result_families"] = families
    result["result_titles"] = sorted(titles, reverse=True)[:40]
    leaked = EXCLUDED_FAMILIES & set(families)
    if leaked:
        raise SystemExit(f"results came from excluded families: {sorted(leaked)}")
    if status != "Done":
        raise SystemExit(f"scan ended as {status!r}")


def main(gmp):
    try:
        wait_for_feed(gmp)
        result["feed_ready_at"] = time.time()
        save()
        wait_for_scanner(gmp)
        config_id = safe_config(gmp)
        save()
        run_scan(gmp, config_id)
        result["scan_done_at"] = time.time()
    except SystemExit as exc:
        result["error"] = str(exc)
        save()
        log(f"FAILED: {exc}")
        sys.exit(1)
    save()
    log("done")


if __name__ == "__gmp__":
    main(gmp)  # noqa: F821 - injected by gvm-script
