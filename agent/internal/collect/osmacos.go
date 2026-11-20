package collect

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/inventory"
)

// maxPkgutilInfo caps the per-package `pkgutil --pkg-info` calls.
const maxPkgutilInfo = 400

func collectMacOS(ctx context.Context, env Env, inv *inventory.Inventory) {
	inv.OS = inventory.OS{Family: "macos", Name: "macOS", Arch: env.GOARCH}
	if out, err := runOK(ctx, env, "sw_vers"); err == nil {
		applySwVers(&inv.OS, ParseSwVers(out))
	} else {
		addErr(inv, "sw_vers", err)
	}
	if out, err := runOK(ctx, env, "uname", "-r"); err == nil {
		inv.OS.Kernel = strings.TrimSpace(string(out))
	}

	if out, err := runOK(ctx, env, "system_profiler", "-json", "-detailLevel", "mini", "SPApplicationsDataType"); err == nil {
		apps, perr := ParseSystemProfilerApps(out)
		if perr == nil {
			inv.Software = append(inv.Software, apps...)
			inv.SoftwareChecked = true
		} else {
			addErr(inv, "applications (system_profiler)", perr)
		}
	} else {
		addErr(inv, "applications (system_profiler)", err)
	}

	// Installer packages that aren't Apple's own (Apple's are the OS itself,
	// covered by the OS version).
	if out, err := runOK(ctx, env, "pkgutil", "--pkgs"); err == nil {
		ids := ThirdPartyPkgIDs(out)
		if len(ids) > maxPkgutilInfo {
			ids = ids[:maxPkgutilInfo]
			inv.Truncated = true
		}
		for _, id := range ids {
			info, err := runOK(ctx, env, "pkgutil", "--pkg-info", id)
			if err != nil {
				continue
			}
			if s, ok := ParsePkgInfo(info); ok {
				inv.Software = append(inv.Software, s)
			}
		}
		inv.SoftwareChecked = true
	} else {
		addErr(inv, "installer packages (pkgutil)", err)
	}

	res, err := env.Run(ctx, "softwareupdate", "--list")
	if err == nil && res.ExitCode == 0 {
		inv.PendingUpdates = ParseSoftwareUpdateList(res.Stdout)
		inv.PendingUpdatesChecked = true
	} else {
		addErr(inv, "pending updates (softwareupdate --list)", cmdErr("softwareupdate", res, err))
	}
}

// ParseSwVers reads "Key:\tvalue" lines.
func ParseSwVers(out []byte) map[string]string {
	kv := map[string]string{}
	for _, l := range lines(out) {
		k, v, ok := strings.Cut(l, ":")
		if ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return kv
}

func applySwVers(o *inventory.OS, kv map[string]string) {
	if n := kv["ProductName"]; n != "" {
		o.Name = n
	}
	o.Version = kv["ProductVersion"]
	o.Build = kv["BuildVersion"]
	if extra := kv["ProductVersionExtra"]; extra != "" {
		// Rapid Security Response, e.g. "(a)".
		o.Release = o.Version + " " + extra
	}
}

type spApps struct {
	Apps []struct {
		Name         string   `json:"_name"`
		Version      string   `json:"version"`
		ObtainedFrom string   `json:"obtained_from"`
		LastModified string   `json:"lastModified"`
		SignedBy     []string `json:"signed_by"`
		Arch         string   `json:"arch_kind"`
	} `json:"SPApplicationsDataType"`
}

// ParseSystemProfilerApps reads `system_profiler -json SPApplicationsDataType`.
// Apps without a version can't be matched and are skipped.
func ParseSystemProfilerApps(out []byte) ([]inventory.Software, error) {
	var parsed spApps
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	var sw []inventory.Software
	for _, a := range parsed.Apps {
		if a.Name == "" || a.Version == "" {
			continue
		}
		s := inventory.Software{Name: a.Name, Version: a.Version, Source: "app", Arch: a.Arch}
		switch {
		case len(a.SignedBy) > 0:
			s.Publisher = developerName(a.SignedBy[0])
		case a.ObtainedFrom != "":
			s.Publisher = a.ObtainedFrom
		}
		if t, err := time.Parse(time.RFC3339, a.LastModified); err == nil {
			s.InstalledAt = t.UTC().Format("2006-01-02")
		}
		sw = append(sw, s)
	}
	return sw, nil
}

var devIDRe = regexp.MustCompile(`^Developer ID Application: (.+?)(?: \([A-Z0-9]+\))?$`)

// developerName turns "Developer ID Application: Google LLC (EQHXZ8M8AV)" into "Google LLC".
func developerName(signer string) string {
	if m := devIDRe.FindStringSubmatch(signer); m != nil {
		return m[1]
	}
	return signer
}

// ThirdPartyPkgIDs filters `pkgutil --pkgs` to non-Apple package ids, sorted.
func ThirdPartyPkgIDs(out []byte) []string {
	var ids []string
	for _, l := range lines(out) {
		id := strings.TrimSpace(l)
		if id == "" || strings.HasPrefix(id, "com.apple.") {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ParsePkgInfo reads `pkgutil --pkg-info <id>`.
func ParsePkgInfo(out []byte) (inventory.Software, bool) {
	kv := map[string]string{}
	for _, l := range lines(out) {
		k, v, ok := strings.Cut(l, ":")
		if ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	id, ver := kv["package-id"], kv["version"]
	if id == "" || ver == "" {
		return inventory.Software{}, false
	}
	s := inventory.Software{Name: id, Version: ver, Source: "pkgutil"}
	if secs, err := strconv.ParseInt(kv["install-time"], 10, 64); err == nil && secs > 0 {
		s.InstalledAt = time.Unix(secs, 0).UTC().Format("2006-01-02")
	}
	return s, true
}

var suLabelRe = regexp.MustCompile(`^\* Label: (.+)$`)

// ParseSoftwareUpdateList reads `softwareupdate --list`. Apple publishes no
// severity, so an update counts as security-relevant when Apple marks it
// Recommended (Apple's OS and Safari updates are where its security fixes ship).
func ParseSoftwareUpdateList(out []byte) []inventory.PendingUpdate {
	var pending []inventory.PendingUpdate
	var cur *inventory.PendingUpdate
	for _, l := range lines(out) {
		trimmed := strings.TrimSpace(l)
		if m := suLabelRe.FindStringSubmatch(trimmed); m != nil {
			pending = append(pending, inventory.PendingUpdate{ID: m[1], Title: m[1], Source: "softwareupdate"})
			cur = &pending[len(pending)-1]
			continue
		}
		if cur == nil || !strings.HasPrefix(trimmed, "Title:") {
			continue
		}
		for _, part := range strings.Split(trimmed, ",") {
			k, v, ok := strings.Cut(strings.TrimSpace(part), ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "Title":
				cur.Title = v
			case "Version":
				cur.Version = v
			case "Recommended":
				cur.Security = strings.EqualFold(v, "YES")
			}
		}
		cur = nil
	}
	return pending
}
