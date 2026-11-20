package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/inventory"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeEnv answers commands from a table keyed by the command name plus its
// first argument; anything not in the table fails as "not found".
type fakeCmd struct {
	stdout string
	stderr string
	exit   int
	err    error
}

func fakeEnv(t *testing.T, goos string, cmds map[string]fakeCmd, files map[string][]byte) (Env, *[]string) {
	t.Helper()
	var calls []string
	return Env{
		Run: func(_ context.Context, name string, args ...string) (Result, error) {
			key := name
			if len(args) > 0 {
				key += " " + args[0]
			}
			// pkgutil --pkg-info <id> is keyed on the id too.
			if name == "pkgutil" && len(args) == 2 && args[0] == "--pkg-info" {
				key += " " + args[1]
			}
			calls = append(calls, key)
			c, ok := cmds[key]
			if !ok {
				return Result{}, errors.New("executable file not found: " + name)
			}
			if c.err != nil {
				return Result{}, c.err
			}
			return Result{Stdout: []byte(c.stdout), Stderr: []byte(c.stderr), ExitCode: c.exit}, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			if b, ok := files[p]; ok {
				return b, nil
			}
			return nil, os.ErrNotExist
		},
		Hostname: func() (string, error) { return "test-host", nil },
		Now:      func() time.Time { return time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC) },
		GOOS:     goos,
		GOARCH:   "amd64",
	}, &calls
}

// ---- Linux ------------------------------------------------------------------

func TestParseOSRelease(t *testing.T) {
	kv := ParseOSRelease(fixture(t, "os-release-ubuntu.txt"))
	if kv["ID"] != "ubuntu" || kv["VERSION_ID"] != "22.04" || kv["NAME"] != "Ubuntu" {
		t.Fatalf("unexpected os-release: %#v", kv)
	}
	if kv["VERSION_CODENAME"] != "jammy" {
		t.Errorf("unquoted value not read: %q", kv["VERSION_CODENAME"])
	}
}

func TestParseOSReleaseIgnoresCommentsAndCRLF(t *testing.T) {
	kv := ParseOSRelease([]byte("# comment\r\nID='debian'\r\nVERSION_ID=\"12\"\r\nnot a pair\r\n"))
	if kv["ID"] != "debian" || kv["VERSION_ID"] != "12" || len(kv) != 2 {
		t.Fatalf("got %#v", kv)
	}
}

func TestParseDpkgQuery(t *testing.T) {
	sw := ParseDpkgQuery(fixture(t, "dpkg-query.txt"))
	// linux-image-old is "rc" (removed, config left): not installed.
	if len(sw) != 4 {
		t.Fatalf("want 4 installed packages, got %d: %#v", len(sw), sw)
	}
	ssl := sw[1]
	if ssl.Name != "libssl3" || ssl.Version != "3.0.2-0ubuntu1.10" || ssl.SourceName != "openssl" || ssl.Source != "dpkg" || ssl.Arch != "amd64" {
		t.Errorf("libssl3 parsed wrong: %#v", ssl)
	}
	if sw[3].Name != "vim" || sw[3].Version != "2:8.2.3995-1ubuntu2.15" {
		t.Errorf("held package with epoch parsed wrong: %#v", sw[3])
	}
}

func TestParseDpkgQueryOldSourceFormat(t *testing.T) {
	sw := ParseDpkgQuery([]byte("libfoo1\t1.2-3\tamd64\tii \tfoo (1.2-2)\t1.2-2\n"))
	if len(sw) != 1 || sw[0].SourceName != "foo" {
		t.Fatalf("got %#v", sw)
	}
}

func TestParseRpmQuery(t *testing.T) {
	sw := ParseRpmQuery(fixture(t, "rpm-qa.txt"))
	if len(sw) != 3 {
		t.Fatalf("want 3 (gpg-pubkey skipped), got %d: %#v", len(sw), sw)
	}
	if sw[0].Name != "openssl" || sw[0].Version != "1:3.0.7-24.el9" || sw[0].SourceName != "openssl" || sw[0].InstalledAt != "2023-11-14" {
		t.Errorf("openssl parsed wrong: %#v", sw[0])
	}
	if sw[1].Version != "5.1.8-6.el9_1" {
		t.Errorf("no-epoch version wrong: %q", sw[1].Version)
	}
	if sw[2].SourceName != "openssl" {
		t.Errorf("source rpm name wrong: %q", sw[2].SourceName)
	}
}

func TestParseAptSimulate(t *testing.T) {
	p := ParseAptSimulate(fixture(t, "apt-get-simulate.txt"))
	if len(p) != 3 {
		t.Fatalf("want 3 Inst lines, got %d: %#v", len(p), p)
	}
	if p[0].ID != "libssl3" || p[0].Version != "3.0.2-0ubuntu1.15" || !p[0].Security || p[0].Source != "apt" {
		t.Errorf("libssl3 wrong: %#v", p[0])
	}
	if p[2].ID != "tzdata" || p[2].Security {
		t.Errorf("tzdata is from -updates only and is not a security update: %#v", p[2])
	}
}

func TestParseAptSimulateNewInstallWithoutOldVersion(t *testing.T) {
	p := ParseAptSimulate([]byte("Inst linux-image-6.8.0-45 (6.8.0-45.45 Ubuntu:24.04/noble-security [amd64])\n"))
	if len(p) != 1 || p[0].ID != "linux-image-6.8.0-45" || !p[0].Security || p[0].Version != "6.8.0-45.45" {
		t.Fatalf("got %#v", p)
	}
}

func TestParseDnfAndSecurity(t *testing.T) {
	p := ParseDnfCheckUpdate(fixture(t, "dnf-check-update.txt"))
	if len(p) != 3 {
		t.Fatalf("want 3 (obsoletes section ignored), got %d: %#v", len(p), p)
	}
	advs := ParseDnfUpdateinfo(fixture(t, "dnf-updateinfo-security.txt"))
	if len(advs) != 3 || advs[0].Severity != "important" {
		t.Fatalf("updateinfo parsed wrong: %#v", advs)
	}
	ApplyDnfSecurity(p, advs)
	if !p[0].Security || p[0].Severity != "important" {
		t.Errorf("openssl should be an important security update: %#v", p[0])
	}
	if !p[1].Security || p[1].ID != "openssl-libs" {
		t.Errorf("openssl-libs should be a security update: %#v", p[1])
	}
	if p[2].Security {
		t.Errorf("tzdata has no advisory: %#v", p[2])
	}
}

func TestApplyDnfSecurityDoesNotMatchLongerNames(t *testing.T) {
	p := []inventory.PendingUpdate{{ID: "openssl"}}
	ApplyDnfSecurity(p, []DnfAdvisory{{ID: "X", Severity: "critical", Package: "openssl-libs-1:3.0.7-25.el9_3.x86_64"}})
	if p[0].Security {
		t.Fatal("openssl must not inherit openssl-libs' advisory")
	}
}

func TestCollectLinuxDebian(t *testing.T) {
	env, _ := fakeEnv(t, "linux", map[string]fakeCmd{
		"uname -r":      {stdout: "5.15.0-101-generic\n"},
		"dpkg-query -W": {stdout: string(fixture(t, "dpkg-query.txt"))},
		"apt-get -s":    {stdout: string(fixture(t, "apt-get-simulate.txt"))},
	}, map[string][]byte{"/etc/os-release": fixture(t, "os-release-ubuntu.txt")})
	inv := Collect(context.Background(), env, "1.0.0")
	if inv.OS.Family != "linux" || inv.OS.DistroID != "ubuntu" || inv.OS.Version != "22.04" || inv.OS.Kernel != "5.15.0-101-generic" {
		t.Errorf("OS wrong: %#v", inv.OS)
	}
	if !inv.SoftwareChecked || len(inv.Software) != 4 {
		t.Errorf("software wrong: checked=%v n=%d", inv.SoftwareChecked, len(inv.Software))
	}
	if !inv.PendingUpdatesChecked || len(inv.PendingUpdates) != 3 {
		t.Errorf("pending wrong: checked=%v n=%d", inv.PendingUpdatesChecked, len(inv.PendingUpdates))
	}
	// rpm isn't installed: that's expected on Debian and must not be reported.
	for _, e := range inv.Errors {
		if strings.Contains(e, "software") {
			t.Errorf("unexpected software error: %s", e)
		}
	}
	if inv.SchemaVersion != inventory.SchemaVersion || inv.Hostname != "test-host" || inv.CollectedAt != "2026-11-20T09:00:00Z" {
		t.Errorf("header wrong: %#v", inv)
	}
}

func TestCollectLinuxRHEL(t *testing.T) {
	env, _ := fakeEnv(t, "linux", map[string]fakeCmd{
		"rpm -qa": {stdout: string(fixture(t, "rpm-qa.txt"))},
		"dnf -q":  {stdout: string(fixture(t, "dnf-check-update.txt")), exit: 100},
	}, map[string][]byte{"/etc/os-release": []byte("ID=\"rhel\"\nVERSION_ID=\"9.3\"\nNAME=\"Red Hat Enterprise Linux\"\n")})
	// "dnf -q" answers both check-update and updateinfo in this fake; the
	// updateinfo call gets check-update's text, which has no advisories, and
	// exits 100, so it is recorded as an error but the pending list stands.
	inv := Collect(context.Background(), env, "1.0.0")
	if !inv.PendingUpdatesChecked || len(inv.PendingUpdates) != 3 {
		t.Fatalf("pending wrong: checked=%v %#v", inv.PendingUpdatesChecked, inv.PendingUpdates)
	}
	if inv.OS.DistroID != "rhel" || inv.OS.Version != "9.3" {
		t.Errorf("OS wrong: %#v", inv.OS)
	}
}

func TestCollectLinuxDnfFailureIsNotClean(t *testing.T) {
	env, _ := fakeEnv(t, "linux", map[string]fakeCmd{
		"rpm -qa": {stdout: string(fixture(t, "rpm-qa.txt"))},
		"dnf -q":  {stderr: "Error: Failed to download metadata for repo 'baseos'\n", exit: 1},
	}, map[string][]byte{"/etc/os-release": []byte("ID=rocky\nVERSION_ID=9.3\n")})
	inv := Collect(context.Background(), env, "1.0.0")
	if inv.PendingUpdatesChecked {
		t.Fatal("a failed check-update must leave pending_updates_checked false")
	}
	if len(inv.Errors) == 0 || !strings.Contains(strings.Join(inv.Errors, "|"), "Failed to download metadata") {
		t.Errorf("error not recorded: %#v", inv.Errors)
	}
	if inv.PendingUpdates == nil {
		t.Error("pending list must serialise as [] not null")
	}
}

func TestCollectLinuxNoPackageManager(t *testing.T) {
	env, _ := fakeEnv(t, "linux", map[string]fakeCmd{}, map[string][]byte{})
	inv := Collect(context.Background(), env, "1.0.0")
	if inv.SoftwareChecked || inv.PendingUpdatesChecked {
		t.Fatalf("nothing could be read, nothing is checked: %#v", inv)
	}
	if len(inv.Errors) < 2 {
		t.Errorf("want os-release and software errors, got %#v", inv.Errors)
	}
}

// ---- macOS ------------------------------------------------------------------

func TestParseSwVers(t *testing.T) {
	kv := ParseSwVers(fixture(t, "sw_vers.txt"))
	if kv["ProductVersion"] != "14.4.1" || kv["BuildVersion"] != "23E224" {
		t.Fatalf("got %#v", kv)
	}
}

func TestParseSystemProfilerApps(t *testing.T) {
	sw, err := ParseSystemProfilerApps(fixture(t, "system_profiler-apps.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sw) != 2 {
		t.Fatalf("want 2 (unversioned skipped), got %#v", sw)
	}
	if sw[0].Name != "Google Chrome" || sw[0].Publisher != "Google LLC" || sw[0].InstalledAt != "2024-04-10" || sw[0].Source != "app" {
		t.Errorf("Chrome wrong: %#v", sw[0])
	}
	if sw[1].Publisher != "apple" {
		t.Errorf("Safari publisher falls back to obtained_from: %#v", sw[1])
	}
	if _, err := ParseSystemProfilerApps([]byte("not json")); err == nil {
		t.Error("bad JSON must be an error, not an empty list")
	}
}

func TestPkgutil(t *testing.T) {
	ids := ThirdPartyPkgIDs(fixture(t, "pkgutil-pkgs.txt"))
	if strings.Join(ids, ",") != "com.microsoft.teams2,us.zoom.pkg.videomeeting" {
		t.Fatalf("got %v", ids)
	}
	s, ok := ParsePkgInfo(fixture(t, "pkgutil-pkg-info-zoom.txt"))
	if !ok || s.Name != "us.zoom.pkg.videomeeting" || s.Version != "5.17.11.31580" || s.InstalledAt != "2024-04-10" || s.Source != "pkgutil" {
		t.Fatalf("got %#v %v", s, ok)
	}
	if _, ok := ParsePkgInfo([]byte("package-id: x\n")); ok {
		t.Error("no version: not a usable package")
	}
}

func TestParseSoftwareUpdateList(t *testing.T) {
	p := ParseSoftwareUpdateList(fixture(t, "softwareupdate-list.txt"))
	if len(p) != 3 {
		t.Fatalf("want 3, got %#v", p)
	}
	if p[0].ID != "macOS Sonoma 14.5-23F79" || p[0].Title != "macOS Sonoma 14.5" || p[0].Version != "14.5" || !p[0].Security {
		t.Errorf("macOS update wrong: %#v", p[0])
	}
	if p[2].Security {
		t.Errorf("a not-recommended update isn't counted: %#v", p[2])
	}
	if len(ParseSoftwareUpdateList([]byte("Software Update Tool\n\nFinding available software\n"))) != 0 {
		t.Error("no updates: empty list")
	}
}

func TestCollectMacOS(t *testing.T) {
	env, calls := fakeEnv(t, "darwin", map[string]fakeCmd{
		"sw_vers":               {stdout: string(fixture(t, "sw_vers.txt"))},
		"uname -r":              {stdout: "23.4.0\n"},
		"system_profiler -json": {stdout: string(fixture(t, "system_profiler-apps.json"))},
		"pkgutil --pkgs":        {stdout: string(fixture(t, "pkgutil-pkgs.txt"))},
		"pkgutil --pkg-info us.zoom.pkg.videomeeting": {stdout: string(fixture(t, "pkgutil-pkg-info-zoom.txt"))},
		"pkgutil --pkg-info com.microsoft.teams2":     {exit: 1, stderr: "No receipt"},
		"softwareupdate --list":                       {stdout: string(fixture(t, "softwareupdate-list.txt"))},
	}, nil)
	inv := Collect(context.Background(), env, "1.0.0")
	if inv.OS.Family != "macos" || inv.OS.Version != "14.4.1" || inv.OS.Build != "23E224" || inv.OS.Kernel != "23.4.0" {
		t.Errorf("OS wrong: %#v", inv.OS)
	}
	if len(inv.Software) != 3 || !inv.SoftwareChecked {
		t.Errorf("want 2 apps + 1 pkg, got %#v", inv.Software)
	}
	if !inv.PendingUpdatesChecked || len(inv.PendingUpdates) != 3 {
		t.Errorf("pending wrong: %#v", inv.PendingUpdates)
	}
	for _, c := range *calls {
		if strings.Contains(c, "com.apple.") {
			t.Errorf("Apple's own packages must not be queried: %s", c)
		}
	}
}

func TestCollectMacOSSoftwareUpdateFails(t *testing.T) {
	env, _ := fakeEnv(t, "darwin", map[string]fakeCmd{
		"sw_vers":               {stdout: string(fixture(t, "sw_vers.txt"))},
		"softwareupdate --list": {exit: 1, stderr: "Cannot connect to the update server"},
	}, nil)
	inv := Collect(context.Background(), env, "1.0.0")
	if inv.PendingUpdatesChecked || inv.SoftwareChecked {
		t.Fatalf("failed sources must not read as checked: %#v", inv)
	}
}

// ---- Windows ----------------------------------------------------------------

func TestApplyWindowsOS(t *testing.T) {
	o := inventory.OS{}
	if err := ApplyWindowsOS(&o, fixture(t, "ps-osinfo.json")); err != nil {
		t.Fatal(err)
	}
	if o.Name != "Microsoft Windows 11 Pro" || o.Version != "10.0.22631.3447" || o.Build != "22631" || o.Release != "23H2" || o.Arch != "64-bit" {
		t.Fatalf("got %#v", o)
	}
	if err := ApplyWindowsOS(&o, []byte("{}")); err == nil {
		t.Error("empty object must be an error")
	}
}

func TestParseUninstallKeys(t *testing.T) {
	sw, err := ParseUninstallKeys(fixture(t, "ps-uninstall.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Duplicate Chrome and the versionless entry are dropped.
	if len(sw) != 3 {
		t.Fatalf("want 3, got %#v", sw)
	}
	if sw[0].Name != "Google Chrome" || sw[0].InstalledAt != "2024-04-10" || sw[0].Source != "registry" || sw[0].Publisher != "Google LLC" {
		t.Errorf("Chrome wrong: %#v", sw[0])
	}
	if sw[2].InstalledAt != "" {
		t.Errorf("a malformed InstallDate is dropped, not guessed: %q", sw[2].InstalledAt)
	}
	single, err := ParseUninstallKeys(fixture(t, "ps-uninstall-single.json"))
	if err != nil || len(single) != 1 || single[0].Name != "Only App" {
		t.Fatalf("a single unrolled object must parse: %#v %v", single, err)
	}
	empty, err := ParseUninstallKeys([]byte("\r\n"))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty output: %#v %v", empty, err)
	}
	if _, err := ParseUninstallKeys([]byte("Get-ItemProperty : Access denied")); err == nil {
		t.Error("non-JSON output must be an error")
	}
}

func TestParseHotfixes(t *testing.T) {
	hf, err := ParseHotfixes(fixture(t, "ps-hotfix.json"))
	if err != nil || len(hf) != 2 || hf[0].ID != "KB5034765" || hf[0].InstalledOn != "2024-02-14" {
		t.Fatalf("got %#v %v", hf, err)
	}
}

func TestParseWindowsUpdates(t *testing.T) {
	p, err := ParseWindowsUpdates(fixture(t, "ps-windows-updates.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 3 {
		t.Fatalf("want 3, got %#v", p)
	}
	if p[0].ID != "KB5036893" || p[0].Severity != "critical" || !p[0].Security || p[0].ReleasedAt != "2024-04-09" || p[0].Source != "windows-update" {
		t.Errorf("cumulative update wrong: %#v", p[0])
	}
	if p[1].Security {
		t.Errorf("MSRT (update rollup, no severity) is not a security update: %#v", p[1])
	}
	if !p[2].Security || p[2].ID != "Microsoft Defender Antivirus antimalware platform update" {
		t.Errorf("Critical Updates category counts, and the title is the id without a KB: %#v", p[2])
	}
}

func TestCollectWindows(t *testing.T) {
	// Every PowerShell call is keyed "powershell.exe -NoProfile"; answer by script.
	var scripts []string
	env, _ := fakeEnv(t, "windows", nil, nil)
	env.Run = func(_ context.Context, name string, args ...string) (Result, error) {
		if name != "powershell.exe" {
			return Result{}, errors.New("not found")
		}
		script := args[len(args)-1]
		scripts = append(scripts, script)
		switch script {
		case PSOSInfo:
			return Result{Stdout: fixture(t, "ps-osinfo.json")}, nil
		case PSUninstallKeys:
			return Result{Stdout: fixture(t, "ps-uninstall.json")}, nil
		case PSHotfixes:
			return Result{Stdout: fixture(t, "ps-hotfix.json")}, nil
		case PSPendingUpdates:
			return Result{ExitCode: 1, Stderr: []byte("Exception from HRESULT: 0x8024402C\r\nmore")}, nil
		}
		return Result{}, errors.New("unexpected script")
	}
	inv := Collect(context.Background(), env, "1.0.0")
	if inv.OS.Version != "10.0.22631.3447" || len(inv.Software) != 3 || len(inv.Hotfixes) != 2 {
		t.Errorf("inventory wrong: %#v", inv)
	}
	if inv.PendingUpdatesChecked {
		t.Error("a failed Windows Update search must not read as checked")
	}
	joined := strings.Join(inv.Errors, "|")
	if !strings.Contains(joined, "0x8024402C") || strings.Contains(joined, "more") {
		t.Errorf("error should carry the first stderr line only: %q", joined)
	}
	if len(scripts) != 4 {
		t.Errorf("want 4 PowerShell calls, got %d", len(scripts))
	}
	for _, s := range scripts {
		if !strings.HasPrefix(s, psPrelude) {
			t.Errorf("script without UTF-8 prelude: %s", s)
		}
	}
}

// ---- Shared -------------------------------------------------------------------

func TestCollectUnsupportedOS(t *testing.T) {
	env, _ := fakeEnv(t, "plan9", nil, nil)
	inv := Collect(context.Background(), env, "1.0.0")
	if inv.OS.Family != "plan9" || len(inv.Errors) != 1 || inv.SoftwareChecked {
		t.Fatalf("got %#v", inv)
	}
}

func TestCollectNeverRunsNetworkTools(t *testing.T) {
	banned := []string{"nmap", "ping", "arp", "netstat", "curl", "wget", "nc", "ss"}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		env, calls := fakeEnv(t, goos, map[string]fakeCmd{}, nil)
		Collect(context.Background(), env, "1.0.0")
		for _, c := range *calls {
			name := strings.Fields(c)[0]
			for _, b := range banned {
				if name == b {
					t.Errorf("%s collector ran %s", goos, name)
				}
			}
		}
	}
}

func TestExecRunReportsExitCodeAndMissingCommand(t *testing.T) {
	if _, err := ExecRun(context.Background(), "hebrides-agent-no-such-command"); err == nil {
		t.Error("a missing command is an error")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	// Re-run the test binary with a flag it rejects: a non-zero exit, not an error.
	res, err := ExecRun(context.Background(), exe, "-test.run=^$", "-test.bogusflag")
	if err != nil {
		t.Fatalf("non-zero exit must not be an error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Error("want a non-zero exit code")
	}
}

func TestSystemEnv(t *testing.T) {
	env := SystemEnv()
	if env.GOOS == "" || env.Run == nil || env.ReadFile == nil || env.Now == nil || env.Hostname == nil {
		t.Fatal("system env incomplete")
	}
}

// ---- Golden payloads (the server's schema test validates these) ---------------

// goldenEnvs are the full-collection fakes above, one per OS.
func goldenEnvs(t *testing.T) map[string]Env {
	linux, _ := fakeEnv(t, "linux", map[string]fakeCmd{
		"uname -r":      {stdout: "5.15.0-101-generic\n"},
		"dpkg-query -W": {stdout: string(fixture(t, "dpkg-query.txt"))},
		"apt-get -s":    {stdout: string(fixture(t, "apt-get-simulate.txt"))},
	}, map[string][]byte{"/etc/os-release": fixture(t, "os-release-ubuntu.txt")})
	macos, _ := fakeEnv(t, "darwin", map[string]fakeCmd{
		"sw_vers":               {stdout: string(fixture(t, "sw_vers.txt"))},
		"uname -r":              {stdout: "23.4.0\n"},
		"system_profiler -json": {stdout: string(fixture(t, "system_profiler-apps.json"))},
		"pkgutil --pkgs":        {stdout: string(fixture(t, "pkgutil-pkgs.txt"))},
		"pkgutil --pkg-info us.zoom.pkg.videomeeting": {stdout: string(fixture(t, "pkgutil-pkg-info-zoom.txt"))},
		"softwareupdate --list":                       {stdout: string(fixture(t, "softwareupdate-list.txt"))},
	}, nil)
	windows, _ := fakeEnv(t, "windows", nil, nil)
	windows.Run = func(_ context.Context, name string, args ...string) (Result, error) {
		switch args[len(args)-1] {
		case PSOSInfo:
			return Result{Stdout: fixture(t, "ps-osinfo.json")}, nil
		case PSUninstallKeys:
			return Result{Stdout: fixture(t, "ps-uninstall.json")}, nil
		case PSHotfixes:
			return Result{Stdout: fixture(t, "ps-hotfix.json")}, nil
		case PSPendingUpdates:
			return Result{Stdout: fixture(t, "ps-windows-updates.json")}, nil
		}
		return Result{}, errors.New("unexpected")
	}
	return map[string]Env{"linux": linux, "macos": macos, "windows": windows}
}

// TestGoldenInventories pins the JSON the agent sends for each fixture set.
// hebridescyber-app/src/lib/deviceAgent/inventorySchema.test.ts validates
// these same files, so a field renamed on one side fails a test on the other.
// Regenerate with UPDATE_GOLDEN=1 go test ./internal/collect/.
func TestGoldenInventories(t *testing.T) {
	for name, env := range goldenEnvs(t) {
		inv := Collect(context.Background(), env, "0.1.0")
		got, err := json.MarshalIndent(inv, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, '\n')
		path := filepath.Join("testdata", "inventory-"+name+".golden.json")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run with UPDATE_GOLDEN=1)", name, err)
		}
		if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
			t.Errorf("%s payload changed; if intended, regenerate with UPDATE_GOLDEN=1 and check the server schema", name)
		}
	}
}
