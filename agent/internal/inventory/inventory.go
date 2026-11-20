// Package inventory is the wire format the agent sends to
// POST /api/agent/inventory. The server's zod schema
// (hebridescyber-app/src/lib/deviceAgent/inventorySchema.ts) is the other
// half of this contract: change both together, and bump SchemaVersion for
// anything that isn't purely additive.
package inventory

import "unicode/utf8"

// SchemaVersion is the payload version the server checks first.
const SchemaVersion = 1

// Limits mirror the server's. The agent trims to them before sending so an
// unusually large machine still reports (with Truncated set) instead of
// being refused with a 413 or 400.
const (
	MaxSoftware       = 5000
	MaxPendingUpdates = 1000
	MaxHotfixes       = 1000
	MaxErrors         = 20
	MaxShortString    = 100 // versions, ids, dates, arch
	MaxNameString     = 200 // names, titles, publishers
	MaxErrorString    = 300
	// MaxBodyBytes is the server's request body limit.
	MaxBodyBytes = 2 * 1024 * 1024
)

// OS describes the operating system.
type OS struct {
	// Family is "windows", "macos" or "linux".
	Family string `json:"family"`
	// Name is the human name: "Microsoft Windows 11 Pro", "macOS", "Ubuntu".
	Name string `json:"name"`
	// Version is the comparable version: "10.0.22631.3447", "14.4.1", "22.04".
	Version string `json:"version"`
	// Build is the vendor build: Windows CurrentBuild, macOS BuildVersion.
	Build string `json:"build,omitempty"`
	// Release is the marketing release: Windows "23H2", Ubuntu "22.04.4 LTS (Jammy Jellyfish)".
	Release string `json:"release,omitempty"`
	Kernel  string `json:"kernel,omitempty"`
	Arch    string `json:"arch"`
	// DistroID / DistroVersionID are os-release ID and VERSION_ID (Linux only).
	DistroID        string `json:"distro_id,omitempty"`
	DistroVersionID string `json:"distro_version_id,omitempty"`
}

// Software is one installed package or application.
type Software struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher,omitempty"`
	// Source is where it was read from: registry, dpkg, rpm, pkgutil, app.
	Source string `json:"source"`
	// InstalledAt is YYYY-MM-DD when the source records it.
	InstalledAt string `json:"installed_at,omitempty"`
	Arch        string `json:"arch,omitempty"`
	// SourceName/SourceVersion are the distro source package (dpkg, rpm), which
	// is what OSV's Debian, Ubuntu and Red Hat advisories are keyed on.
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// PendingUpdate is an update the OS's own update source says is available
// and not installed.
type PendingUpdate struct {
	// ID is stable across reports: KB number, package name, softwareupdate label.
	ID      string `json:"id"`
	Title   string `json:"title"`
	Version string `json:"version,omitempty"`
	// Severity is the vendor's rating, lower-cased, when it gives one:
	// critical, important, moderate, low.
	Severity string `json:"severity,omitempty"`
	// Security is true when the vendor classes it as a security update.
	Security bool `json:"security"`
	// ReleasedAt is YYYY-MM-DD when the source gives a release date.
	ReleasedAt string `json:"released_at,omitempty"`
	Source     string `json:"source"`
}

// Hotfix is an installed Windows update (Get-HotFix).
type Hotfix struct {
	ID          string `json:"id"`
	InstalledOn string `json:"installed_on,omitempty"`
	Description string `json:"description,omitempty"`
}

// Inventory is the whole report.
type Inventory struct {
	SchemaVersion int    `json:"schema_version"`
	AgentVersion  string `json:"agent_version"`
	// CollectedAt is RFC 3339 UTC.
	CollectedAt string     `json:"collected_at"`
	Hostname    string     `json:"hostname"`
	OS          OS         `json:"os"`
	Software    []Software `json:"software"`
	// SoftwareChecked is false when no software source could be read, so the
	// server never treats an empty list as "nothing installed".
	SoftwareChecked bool            `json:"software_checked"`
	PendingUpdates  []PendingUpdate `json:"pending_updates"`
	// PendingUpdatesChecked is false when the update source failed or isn't
	// supported: the server then reports the device as "unknown", never as
	// up to date.
	PendingUpdatesChecked bool     `json:"pending_updates_checked"`
	Hotfixes              []Hotfix `json:"hotfixes"`
	// Truncated is true when a list was cut to its limit.
	Truncated bool `json:"truncated"`
	// Errors are short per-collector failure notes.
	Errors []string `json:"errors"`
}

// Clip cuts s to at most n bytes on a rune boundary.
func Clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Normalise trims every list and string to the server's limits, and makes
// nil lists empty so they serialise as [] rather than null.
func (inv *Inventory) Normalise() {
	inv.Hostname = Clip(inv.Hostname, MaxNameString)
	inv.AgentVersion = Clip(inv.AgentVersion, MaxShortString)
	o := &inv.OS
	o.Family = Clip(o.Family, MaxShortString)
	o.Name = Clip(o.Name, MaxNameString)
	o.Version = Clip(o.Version, MaxShortString)
	o.Build = Clip(o.Build, MaxShortString)
	o.Release = Clip(o.Release, MaxNameString)
	o.Kernel = Clip(o.Kernel, MaxShortString)
	o.Arch = Clip(o.Arch, MaxShortString)
	o.DistroID = Clip(o.DistroID, MaxShortString)
	o.DistroVersionID = Clip(o.DistroVersionID, MaxShortString)

	if len(inv.Software) > MaxSoftware {
		inv.Software = inv.Software[:MaxSoftware]
		inv.Truncated = true
	}
	for i := range inv.Software {
		s := &inv.Software[i]
		s.Name = Clip(s.Name, MaxNameString)
		s.Version = Clip(s.Version, MaxShortString)
		s.Publisher = Clip(s.Publisher, MaxNameString)
		s.Source = Clip(s.Source, MaxShortString)
		s.InstalledAt = Clip(s.InstalledAt, MaxShortString)
		s.Arch = Clip(s.Arch, MaxShortString)
		s.SourceName = Clip(s.SourceName, MaxNameString)
		s.SourceVersion = Clip(s.SourceVersion, MaxShortString)
	}
	if len(inv.PendingUpdates) > MaxPendingUpdates {
		inv.PendingUpdates = inv.PendingUpdates[:MaxPendingUpdates]
		inv.Truncated = true
	}
	for i := range inv.PendingUpdates {
		p := &inv.PendingUpdates[i]
		p.ID = Clip(p.ID, MaxNameString)
		p.Title = Clip(p.Title, MaxNameString)
		p.Version = Clip(p.Version, MaxShortString)
		p.Severity = Clip(p.Severity, MaxShortString)
		p.ReleasedAt = Clip(p.ReleasedAt, MaxShortString)
		p.Source = Clip(p.Source, MaxShortString)
	}
	if len(inv.Hotfixes) > MaxHotfixes {
		inv.Hotfixes = inv.Hotfixes[:MaxHotfixes]
		inv.Truncated = true
	}
	for i := range inv.Hotfixes {
		h := &inv.Hotfixes[i]
		h.ID = Clip(h.ID, MaxShortString)
		h.InstalledOn = Clip(h.InstalledOn, MaxShortString)
		h.Description = Clip(h.Description, MaxNameString)
	}
	if len(inv.Errors) > MaxErrors {
		inv.Errors = inv.Errors[:MaxErrors]
	}
	for i := range inv.Errors {
		inv.Errors[i] = Clip(inv.Errors[i], MaxErrorString)
	}
	if inv.Software == nil {
		inv.Software = []Software{}
	}
	if inv.PendingUpdates == nil {
		inv.PendingUpdates = []PendingUpdate{}
	}
	if inv.Hotfixes == nil {
		inv.Hotfixes = []Hotfix{}
	}
	if inv.Errors == nil {
		inv.Errors = []string{}
	}
}
