package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-barvas/hebrides-cyber/agent/internal/inventory"
)

// Every script starts by forcing UTF-8 output and silencing progress bars.
const psPrelude = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"

// PSOSInfo reads the OS from WMI and the CurrentVersion registry key.
const PSOSInfo = psPrelude + `$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';` +
	`$os=Get-CimInstance Win32_OperatingSystem;` +
	`[pscustomobject]@{caption=[string]$os.Caption;version=[string]$os.Version;build=[string]$cv.CurrentBuild;ubr=[string]$cv.UBR;display_version=[string]$cv.DisplayVersion;arch=[string]$os.OSArchitecture}|ConvertTo-Json -Compress`

// PSUninstallKeys reads the three uninstall registry keys. System components
// and child entries (updates to a parent product) are left out, as
// Programs and Features does.
const PSUninstallKeys = psPrelude + `$p='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*';` +
	`ConvertTo-Json -Compress -InputObject @(Get-ItemProperty -Path $p -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName}|ForEach-Object{[pscustomobject]@{name=[string]$_.DisplayName;version=[string]$_.DisplayVersion;publisher=[string]$_.Publisher;install_date=[string]$_.InstallDate}})`

// PSHotfixes lists installed updates with Get-HotFix.
const PSHotfixes = psPrelude + `ConvertTo-Json -Compress -InputObject @(Get-HotFix|ForEach-Object{[pscustomobject]@{id=[string]$_.HotFixID;installed_on=$(if($_.InstalledOn){$_.InstalledOn.ToString('yyyy-MM-dd')}else{''});description=[string]$_.Description}})`

// PSPendingUpdates asks the Windows Update Agent which software updates are
// applicable and not installed, the same search Settings > Windows Update runs.
const PSPendingUpdates = psPrelude + `$s=New-Object -ComObject Microsoft.Update.Session;$r=$s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'");` +
	`ConvertTo-Json -Compress -Depth 3 -InputObject @($r.Updates|ForEach-Object{[pscustomobject]@{title=[string]$_.Title;kbs=@($_.KBArticleIDs|ForEach-Object{[string]$_});severity=[string]$_.MsrcSeverity;released=$(if($_.LastDeploymentChangeTime){$_.LastDeploymentChangeTime.ToString('yyyy-MM-dd')}else{''});categories=@($_.Categories|ForEach-Object{[string]$_.Name})}})`

func powershell(ctx context.Context, env Env, script string) ([]byte, error) {
	out, err := runOK(ctx, env, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return nil, err
	}
	return stripBOM(out), nil
}

func collectWindows(ctx context.Context, env Env, inv *inventory.Inventory) {
	inv.OS = inventory.OS{Family: "windows", Name: "Windows", Arch: env.GOARCH}
	if out, err := powershell(ctx, env, PSOSInfo); err == nil {
		if perr := ApplyWindowsOS(&inv.OS, out); perr != nil {
			addErr(inv, "os version", perr)
		}
	} else {
		addErr(inv, "os version", err)
	}

	if out, err := powershell(ctx, env, PSUninstallKeys); err == nil {
		sw, perr := ParseUninstallKeys(out)
		if perr == nil {
			inv.Software = sw
			inv.SoftwareChecked = true
		} else {
			addErr(inv, "software (registry uninstall keys)", perr)
		}
	} else {
		addErr(inv, "software (registry uninstall keys)", err)
	}

	if out, err := powershell(ctx, env, PSHotfixes); err == nil {
		hf, perr := ParseHotfixes(out)
		if perr == nil {
			inv.Hotfixes = hf
		} else {
			addErr(inv, "hotfixes (Get-HotFix)", perr)
		}
	} else {
		addErr(inv, "hotfixes (Get-HotFix)", err)
	}

	if out, err := powershell(ctx, env, PSPendingUpdates); err == nil {
		pending, perr := ParseWindowsUpdates(out)
		if perr == nil {
			inv.PendingUpdates = pending
			inv.PendingUpdatesChecked = true
		} else {
			addErr(inv, "pending updates (Windows Update)", perr)
		}
	} else {
		addErr(inv, "pending updates (Windows Update)", err)
	}
}

// decodeArray accepts a JSON array, a single object (older PowerShell
// unrolls one-element arrays) or empty output.
func decodeArray[T any](out []byte) ([]T, error) {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		var one T
		if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
			return nil, err
		}
		return []T{one}, nil
	}
	var many []T
	if err := json.Unmarshal([]byte(trimmed), &many); err != nil {
		return nil, err
	}
	return many, nil
}

type psOS struct {
	Caption        string `json:"caption"`
	Version        string `json:"version"`
	Build          string `json:"build"`
	UBR            string `json:"ubr"`
	DisplayVersion string `json:"display_version"`
	Arch           string `json:"arch"`
}

// ApplyWindowsOS fills o from PSOSInfo output. Version becomes
// "major.minor.build.UBR" (10.0.22631.3447), the form Microsoft's
// release-health tables and the CVE index's Windows criteria use.
func ApplyWindowsOS(o *inventory.OS, out []byte) error {
	var p psOS
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(stripBOM(out)))), &p); err != nil {
		return err
	}
	if p.Caption == "" && p.Version == "" {
		return errors.New("no OS version in output")
	}
	if p.Caption != "" {
		o.Name = strings.TrimSpace(p.Caption)
	}
	o.Version = p.Version
	o.Build = p.Build
	if p.Build != "" && p.UBR != "" {
		// Win32_OperatingSystem.Version is "10.0.22631"; add the UBR.
		parts := strings.Split(p.Version, ".")
		if len(parts) >= 2 {
			o.Version = parts[0] + "." + parts[1] + "." + p.Build + "." + p.UBR
		}
	}
	o.Release = p.DisplayVersion
	if p.Arch != "" {
		o.Arch = p.Arch
	}
	return nil
}

type psSoftware struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
}

// ParseUninstallKeys reads PSUninstallKeys output, dropping duplicates (the
// same product registered under both views) and entries with no version.
func ParseUninstallKeys(out []byte) ([]inventory.Software, error) {
	rows, err := decodeArray[psSoftware](stripBOM(out))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var sw []inventory.Software
	for _, r := range rows {
		name, ver := strings.TrimSpace(r.Name), strings.TrimSpace(r.Version)
		if name == "" || ver == "" {
			continue
		}
		key := strings.ToLower(name) + "\x00" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		sw = append(sw, inventory.Software{
			Name:        name,
			Version:     ver,
			Publisher:   strings.TrimSpace(r.Publisher),
			Source:      "registry",
			InstalledAt: registryDate(r.InstallDate),
		})
	}
	return sw, nil
}

// registryDate turns InstallDate's "20240315" into "2024-03-15".
func registryDate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) != 8 {
		return ""
	}
	t, err := time.Parse("20060102", s)
	if err != nil {
		return ""
	}
	return t.Format("2006-01-02")
}

type psHotfix struct {
	ID          string `json:"id"`
	InstalledOn string `json:"installed_on"`
	Description string `json:"description"`
}

// ParseHotfixes reads PSHotfixes output.
func ParseHotfixes(out []byte) ([]inventory.Hotfix, error) {
	rows, err := decodeArray[psHotfix](stripBOM(out))
	if err != nil {
		return nil, err
	}
	var hf []inventory.Hotfix
	for _, r := range rows {
		if r.ID == "" {
			continue
		}
		hf = append(hf, inventory.Hotfix{ID: r.ID, InstalledOn: r.InstalledOn, Description: r.Description})
	}
	return hf, nil
}

type psUpdate struct {
	Title      string   `json:"title"`
	KBs        []string `json:"kbs"`
	Severity   string   `json:"severity"`
	Released   string   `json:"released"`
	Categories []string `json:"categories"`
}

// ParseWindowsUpdates reads PSPendingUpdates output. An update is a
// security update when Microsoft gives it an MSRC severity or files it under
// Security Updates or Critical Updates.
func ParseWindowsUpdates(out []byte) ([]inventory.PendingUpdate, error) {
	rows, err := decodeArray[psUpdate](stripBOM(out))
	if err != nil {
		return nil, err
	}
	var pending []inventory.PendingUpdate
	for i, r := range rows {
		id := ""
		if len(r.KBs) > 0 && r.KBs[0] != "" {
			id = "KB" + strings.TrimPrefix(strings.ToUpper(r.KBs[0]), "KB")
		} else if r.Title != "" {
			id = r.Title
		} else {
			id = "update-" + strconv.Itoa(i+1)
		}
		security := r.Severity != ""
		for _, c := range r.Categories {
			if strings.EqualFold(c, "Security Updates") || strings.EqualFold(c, "Critical Updates") {
				security = true
			}
		}
		pending = append(pending, inventory.PendingUpdate{
			ID:         id,
			Title:      r.Title,
			Severity:   strings.ToLower(strings.TrimSpace(r.Severity)),
			Security:   security,
			ReleasedAt: r.Released,
			Source:     "windows-update",
		})
	}
	return pending, nil
}
