package collect

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/inventory"
)

// dpkg-query format: one tab-separated line per package.
const dpkgFormat = "${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n"

// rpm query format. %{EPOCH} is "(none)" when unset; %{INSTALLTIME} is Unix seconds.
const rpmFormat = "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\t%{SOURCERPM}\n"

func collectLinux(ctx context.Context, env Env, inv *inventory.Inventory) {
	inv.OS = inventory.OS{Family: "linux", Arch: env.GOARCH}
	if data, err := env.ReadFile("/etc/os-release"); err == nil {
		applyOSRelease(&inv.OS, ParseOSRelease(data))
	} else if data, err := env.ReadFile("/usr/lib/os-release"); err == nil {
		applyOSRelease(&inv.OS, ParseOSRelease(data))
	} else {
		addErr(inv, "os-release", err)
	}
	if out, err := runOK(ctx, env, "uname", "-r"); err == nil {
		inv.OS.Kernel = strings.TrimSpace(string(out))
	}

	// Software: dpkg first, then rpm. A machine with both (rare) reports both.
	var softwareErrs []error
	if out, err := runOK(ctx, env, "dpkg-query", "-W", "-f="+dpkgFormat); err == nil {
		inv.Software = append(inv.Software, ParseDpkgQuery(out)...)
		inv.SoftwareChecked = true
	} else {
		softwareErrs = append(softwareErrs, err)
	}
	if out, err := runOK(ctx, env, "rpm", "-qa", "--qf", rpmFormat); err == nil {
		inv.Software = append(inv.Software, ParseRpmQuery(out)...)
		inv.SoftwareChecked = true
	} else {
		softwareErrs = append(softwareErrs, err)
	}
	if !inv.SoftwareChecked {
		addErr(inv, "software (dpkg, rpm)", errors.Join(softwareErrs...))
	}

	// Pending updates, from whichever package manager the machine uses. The
	// agent never runs `apt update`: that needs root and changes the system.
	// It reports what the package lists already know.
	switch {
	case hasSource(inv.Software, "dpkg"):
		res, err := env.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
		if err == nil && res.ExitCode == 0 {
			inv.PendingUpdates = ParseAptSimulate(res.Stdout)
			inv.PendingUpdatesChecked = true
		} else {
			addErr(inv, "pending updates (apt-get -s)", cmdErr("apt-get", res, err))
		}
	case hasSource(inv.Software, "rpm"):
		collectDnf(ctx, env, inv)
	default:
		inv.Errors = append(inv.Errors, "pending updates: no supported package manager (dpkg/apt or rpm/dnf)")
	}
}

func collectDnf(ctx context.Context, env Env, inv *inventory.Inventory) {
	tool := "dnf"
	res, err := env.Run(ctx, tool, "-q", "check-update")
	if err != nil {
		tool = "yum"
		res, err = env.Run(ctx, tool, "-q", "check-update")
	}
	// check-update: 0 = nothing pending, 100 = updates listed, else failure.
	if err != nil || (res.ExitCode != 0 && res.ExitCode != 100) {
		addErr(inv, "pending updates ("+tool+" check-update)", cmdErr(tool, res, err))
		return
	}
	pending := ParseDnfCheckUpdate(res.Stdout)
	if sec, err := runOK(ctx, env, tool, "-q", "updateinfo", "list", "--security", "--available"); err == nil {
		ApplyDnfSecurity(pending, ParseDnfUpdateinfo(sec))
	} else {
		addErr(inv, "security classification ("+tool+" updateinfo)", err)
	}
	inv.PendingUpdates = pending
	inv.PendingUpdatesChecked = true
}

func cmdErr(name string, res Result, err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("%s exited %d: %s", name, res.ExitCode, firstLine(res.Stderr))
}

func hasSource(sw []inventory.Software, source string) bool {
	for _, s := range sw {
		if s.Source == source {
			return true
		}
	}
	return false
}

// ParseOSRelease parses /etc/os-release KEY=value lines, unquoting values.
func ParseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	for _, l := range lines(data) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = strings.ReplaceAll(v, `\"`, `"`)
	}
	return out
}

func applyOSRelease(o *inventory.OS, kv map[string]string) {
	o.Name = kv["NAME"]
	o.Version = kv["VERSION_ID"]
	o.Release = kv["VERSION"]
	if o.Release == "" {
		o.Release = kv["PRETTY_NAME"]
	}
	o.DistroID = strings.ToLower(kv["ID"])
	o.DistroVersionID = kv["VERSION_ID"]
}

// ParseDpkgQuery parses dpkgFormat output, keeping only installed packages
// (status "ii", or "hi" for held).
func ParseDpkgQuery(out []byte) []inventory.Software {
	var sw []inventory.Software
	for _, l := range lines(out) {
		f := strings.Split(l, "\t")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		status := strings.TrimSpace(f[3])
		if len(status) < 2 || status[1] != 'i' {
			continue
		}
		s := inventory.Software{Name: f[0], Version: f[1], Arch: f[2], Source: "dpkg"}
		if len(f) >= 6 {
			// ${source:Package} can carry "(version)" on old dpkg; keep the name.
			src := strings.TrimSpace(f[4])
			if i := strings.IndexByte(src, ' '); i > 0 {
				src = src[:i]
			}
			s.SourceName = src
			s.SourceVersion = strings.TrimSpace(f[5])
		}
		sw = append(sw, s)
	}
	return sw
}

var srpmRe = regexp.MustCompile(`^(.+)-[^-]+-[^-]+\.src\.rpm$`)

// ParseRpmQuery parses rpmFormat output. Version is
// "[epoch:]version-release", the form OSV's Red Hat ecosystems use.
func ParseRpmQuery(out []byte) []inventory.Software {
	var sw []inventory.Software
	for _, l := range lines(out) {
		f := strings.Split(l, "\t")
		if len(f) < 7 || f[0] == "" || f[0] == "gpg-pubkey" {
			continue
		}
		ver := f[2] + "-" + f[3]
		if f[1] != "(none)" && f[1] != "" {
			ver = f[1] + ":" + ver
		}
		s := inventory.Software{Name: f[0], Version: ver, Arch: f[4], Source: "rpm"}
		if secs, err := strconv.ParseInt(f[5], 10, 64); err == nil && secs > 0 {
			s.InstalledAt = time.Unix(secs, 0).UTC().Format("2006-01-02")
		}
		if m := srpmRe.FindStringSubmatch(f[6]); m != nil {
			s.SourceName = m[1]
		}
		sw = append(sw, s)
	}
	return sw
}

// Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
var aptInstRe = regexp.MustCompile(`^Inst (\S+)(?: \[([^\]]*)\])? \((\S+) ([^\[]*?)(?: \[[^\]]*\])?\)`)

// ParseAptSimulate reads `apt-get -s dist-upgrade` output. An update counts
// as a security update when it comes from a *-security pocket.
func ParseAptSimulate(out []byte) []inventory.PendingUpdate {
	var pending []inventory.PendingUpdate
	for _, l := range lines(out) {
		m := aptInstRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		repos := m[4]
		pending = append(pending, inventory.PendingUpdate{
			ID:       m[1],
			Title:    m[1],
			Version:  m[3],
			Security: strings.Contains(strings.ToLower(repos), "security"),
			Source:   "apt",
		})
	}
	return pending
}

// ParseDnfCheckUpdate reads `dnf -q check-update`: "name.arch  version  repo".
// The "Obsoleting Packages" section that can follow is ignored.
func ParseDnfCheckUpdate(out []byte) []inventory.PendingUpdate {
	var pending []inventory.PendingUpdate
	seen := map[string]bool{}
	for _, l := range lines(out) {
		if strings.HasPrefix(l, "Obsoleting") {
			break
		}
		f := strings.Fields(l)
		if len(f) != 3 || strings.HasPrefix(l, " ") {
			continue
		}
		name := f[0]
		if i := strings.LastIndexByte(name, '.'); i > 0 {
			name = name[:i]
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		pending = append(pending, inventory.PendingUpdate{ID: name, Title: name, Version: f[1], Source: "dnf"})
	}
	return pending
}

// DnfAdvisory is one line of `dnf updateinfo list --security`.
type DnfAdvisory struct {
	ID       string
	Severity string
	Package  string // NEVRA
}

// ParseDnfUpdateinfo reads "RHSA-2024:1234 Important/Sec. openssl-1:3.0.7-25.el9_3.x86_64".
func ParseDnfUpdateinfo(out []byte) []DnfAdvisory {
	var advs []DnfAdvisory
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) != 3 {
			continue
		}
		sev, _, _ := strings.Cut(f[1], "/")
		advs = append(advs, DnfAdvisory{ID: f[0], Severity: strings.ToLower(sev), Package: f[2]})
	}
	return advs
}

var severityRank = map[string]int{"critical": 4, "important": 3, "moderate": 2, "low": 1}

// ApplyDnfSecurity marks pending updates covered by a security advisory,
// keeping the highest severity seen.
func ApplyDnfSecurity(pending []inventory.PendingUpdate, advs []DnfAdvisory) {
	for i := range pending {
		p := &pending[i]
		for _, a := range advs {
			if !strings.HasPrefix(a.Package, p.ID+"-") {
				continue
			}
			// The rest must start with a version digit or an epoch, so
			// "openssl" doesn't swallow "openssl-libs-…".
			rest := a.Package[len(p.ID)+1:]
			if rest == "" || rest[0] < '0' || rest[0] > '9' {
				continue
			}
			p.Security = true
			if severityRank[a.Severity] > severityRank[p.Severity] {
				p.Severity = a.Severity
			}
		}
	}
}
