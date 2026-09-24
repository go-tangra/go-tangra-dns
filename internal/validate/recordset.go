package validate

import (
	"fmt"
	"strings"

	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
)

// MaxComment bounds a record set's comment.
const MaxComment = 512

// RecordValue is one value of a record set input.
type RecordValue struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled,omitempty"`
}

// RecordSetInput is a record set as a caller submits it (contracts §A):
// Name is "@", relative or absolute; Type is one of EditableTypes.
type RecordSetInput struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	TTL     int           `json:"ttl"`
	Values  []RecordValue `json:"values"`
	Comment string        `json:"comment,omitempty"`
}

// Limits bound record sets (config records.*).
type Limits struct {
	MinTTL    int
	MaxTTL    int
	MaxValues int
}

// DefaultLimits are the configuration defaults (TTL 60–604800, 100 values).
var DefaultLimits = Limits{MinTTL: 60, MaxTTL: 604800, MaxValues: 100}

// RecordSet is DefaultLimits.RecordSet.
func RecordSet(zone string, in RecordSetInput, existing []pdns.RRset) (pdns.RRset, error) {
	return DefaultLimits.RecordSet(zone, in, existing)
}

// RecordSet validates a record set for zone against the zone's existing
// rrsets (the rrset being replaced — same name and type — is ignored; a
// renamed rrset's original must be left out by the caller) and returns the
// PowerDNS REPLACE change: qualified owner name, upper-case type, TTL within
// the limits, 1..MaxValues canonical and distinct values with their disabled
// flags, and the optional comment. A CNAME is never at the apex, holds exactly
// one value and never shares its name with other data.
func (l Limits) RecordSet(zone string, in RecordSetInput, existing []pdns.RRset) (pdns.RRset, error) {
	z, err := canonicalZone(zone)
	if err != nil {
		return pdns.RRset{}, err
	}
	t, re := editableType(in.Type)
	if re != nil {
		return pdns.RRset{}, re
	}
	name, err := RecordName(z, in.Name)
	if err != nil {
		return pdns.RRset{}, err
	}
	if in.TTL < l.MinTTL || in.TTL > l.MaxTTL {
		return pdns.RRset{}, recErr("ttl", "ttl must be within [%d, %d] seconds", l.MinTTL, l.MaxTTL)
	}
	if len(in.Values) == 0 || len(in.Values) > l.MaxValues {
		return pdns.RRset{}, recErr("values", "between 1 and %d values are required", l.MaxValues)
	}
	if len(in.Comment) > MaxComment || hasControl(in.Comment) {
		return pdns.RRset{}, recErr("comment", "the comment must be at most %d characters without control characters", MaxComment)
	}
	if t == "CNAME" {
		if name == z {
			return pdns.RRset{}, recErr("type", "a CNAME is not allowed at the zone apex")
		}
		if len(in.Values) > 1 {
			return pdns.RRset{}, recErr("values", "a CNAME set holds exactly one value")
		}
	}
	for _, e := range existing {
		if !strings.EqualFold(e.Name, name) || strings.EqualFold(e.Type, t) {
			continue
		}
		if t == "CNAME" {
			return pdns.RRset{}, recErr("type", "other data exists at %s; a CNAME must be alone at its name", name)
		}
		if strings.EqualFold(e.Type, "CNAME") {
			return pdns.RRset{}, recErr("type", "a CNAME exists at %s; no other data is allowed there", name)
		}
	}
	out := pdns.RRset{Name: name, Type: t, TTL: uint32(in.TTL), ChangeType: pdns.ChangeReplace} // #nosec G115 -- bounded by Limits (<= 2^31-1)
	seen := map[string]bool{}
	for i, v := range in.Values {
		c, re := content(t, z, v.Content)
		field := fmt.Sprintf("values[%d].content", i)
		if re != nil {
			return pdns.RRset{}, &RecordError{Field: field, Msg: re.Msg}
		}
		if seen[c] {
			return pdns.RRset{}, recErr(field, "duplicate value")
		}
		seen[c] = true
		out.Records = append(out.Records, pdns.Record{Content: c, Disabled: v.Disabled})
	}
	// Always explicit: an empty list clears an existing comment in PowerDNS
	// (a nil list would keep it).
	out.Comments = []pdns.Comment{}
	if c := strings.TrimSpace(in.Comment); c != "" {
		out.Comments = []pdns.Comment{{Content: c}}
	}
	return out, nil
}
