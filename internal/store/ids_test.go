package store

import (
	"regexp"
	"sort"
	"testing"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewIDMonotonicAndWellFormed(t *testing.T) {
	ids := make([]string, 5000)
	for i := range ids {
		ids[i] = NewID()
		if !uuidRE.MatchString(ids[i]) {
			t.Fatalf("bad uuidv7 %q", ids[i])
		}
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatal("ids minted in sequence must sort in creation order")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate %s", id)
		}
		seen[id] = true
	}
}
