package inventory

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClipKeepsRuneBoundary(t *testing.T) {
	s := strings.Repeat("é", 10) // 2 bytes each
	got := Clip(s, 5)
	if !utf8.ValidString(got) || len(got) != 4 {
		t.Fatalf("got %q (%d bytes)", got, len(got))
	}
	if Clip("short", 100) != "short" {
		t.Fatal("short strings are unchanged")
	}
}

func TestNormaliseTrimsListsAndStrings(t *testing.T) {
	inv := Inventory{Hostname: strings.Repeat("h", 500)}
	for i := 0; i < MaxSoftware+10; i++ {
		inv.Software = append(inv.Software, Software{Name: strings.Repeat("n", 300), Version: "1"})
	}
	for i := 0; i < MaxPendingUpdates+1; i++ {
		inv.PendingUpdates = append(inv.PendingUpdates, PendingUpdate{ID: "x"})
	}
	for i := 0; i < MaxHotfixes+1; i++ {
		inv.Hotfixes = append(inv.Hotfixes, Hotfix{ID: "KB1"})
	}
	for i := 0; i < MaxErrors+5; i++ {
		inv.Errors = append(inv.Errors, strings.Repeat("e", 1000))
	}
	inv.Normalise()
	if len(inv.Software) != MaxSoftware || len(inv.PendingUpdates) != MaxPendingUpdates || len(inv.Hotfixes) != MaxHotfixes || len(inv.Errors) != MaxErrors {
		t.Fatal("lists not trimmed")
	}
	if !inv.Truncated {
		t.Error("Truncated not set")
	}
	if len(inv.Hostname) != MaxNameString || len(inv.Software[0].Name) != MaxNameString || len(inv.Errors[0]) != MaxErrorString {
		t.Error("strings not trimmed")
	}
}

func TestNormaliseMakesNilListsEmpty(t *testing.T) {
	inv := Inventory{}
	inv.Normalise()
	b, _ := json.Marshal(inv)
	for _, k := range []string{`"software":[]`, `"pending_updates":[]`, `"hotfixes":[]`, `"errors":[]`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("want %s in %s", k, b)
		}
	}
	if inv.Truncated {
		t.Error("nothing was cut")
	}
}
