package templates

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/validate"
)

// Placeholder is replaced by the zone name (without its trailing dot) in
// template record names and contents.
const Placeholder = "[ZONE]"

// placeholderZone is what templates are validated against when saved.
const placeholderZone = "placeholder.example."

// MaxPriority bounds MX preference / SRV priority.
const MaxPriority = 65535

// priorityFields is the field count of a full MX/SRV value (priority first).
var priorityFields = map[string]int{"MX": 2, "SRV": 4}

func recordErr(i int, field, msg string) error {
	return &validate.RecordError{Field: fmt.Sprintf("records[%d].%s", i, field), Msg: msg}
}

// withPriority applies a template record's priority to MX/SRV content that
// does not carry one ("mail.[ZONE]." + 10 → "10 mail.[ZONE]."). A value that
// already starts with its priority is kept, and giving the priority twice is
// refused; other types take no priority (the source dropped it silently).
func withPriority(i int, r store.TemplateRecord, typ, content string) (string, error) {
	if r.Priority < 0 || r.Priority > MaxPriority {
		return "", recordErr(i, "priority", fmt.Sprintf("priority must be within [0, %d]", MaxPriority))
	}
	full, ok := priorityFields[typ]
	if !ok {
		if r.Priority != 0 {
			return "", recordErr(i, "priority", "priority applies to MX and SRV records only")
		}
		return content, nil
	}
	switch len(strings.Fields(content)) {
	case full - 1:
		return strconv.Itoa(r.Priority) + " " + content, nil
	case full:
		if r.Priority != 0 {
			return "", recordErr(i, "priority", "the value already starts with a priority")
		}
	}
	return content, nil
}

type group struct {
	first int
	in    validate.RecordSetInput
}

// ExpandRecords expands template records for zone: [ZONE] is replaced in
// names and contents, "@"/empty names are the apex and relative names are
// qualified, priorities are applied to MX/SRV, records with the same (name,
// type) are merged into one rrset (the first record's TTL), and every set is
// validated against the zone (per-type content, TTL limits, CNAME rules).
// Errors name the offending record ("records[i]...").
func ExpandRecords(l validate.Limits, zone string, recs []store.TemplateRecord) ([]pdns.RRset, error) {
	z, err := validate.ZoneName(zone)
	if err != nil {
		return nil, err
	}
	if len(recs) > store.MaxTemplateRecords {
		return nil, fmt.Errorf("%w: at most %d records", ErrInvalid, store.MaxTemplateRecords)
	}
	bare := strings.TrimSuffix(z, ".")
	groups := map[string]*group{}
	var order []string
	for i, r := range recs {
		typ := strings.ToUpper(strings.TrimSpace(r.Type))
		name := strings.TrimSpace(strings.ReplaceAll(r.Name, Placeholder, bare))
		if name == "" {
			name = "@"
		}
		content, err := withPriority(i, r, typ, strings.TrimSpace(strings.ReplaceAll(r.Content, Placeholder, bare)))
		if err != nil {
			return nil, err
		}
		one := validate.RecordSetInput{Name: name, Type: typ, TTL: r.TTL, Values: []validate.RecordValue{{Content: content}}}
		rr, err := l.RecordSet(z, one, nil)
		if err != nil {
			return nil, indexed(i, err)
		}
		key := rr.Name + " " + rr.Type
		g, ok := groups[key]
		if !ok {
			g = &group{first: i, in: validate.RecordSetInput{Name: rr.Name, Type: rr.Type, TTL: r.TTL}}
			groups[key] = g
			order = append(order, key)
		}
		g.in.Values = append(g.in.Values, validate.RecordValue{Content: content})
	}
	sort.Strings(order)
	out := make([]pdns.RRset, 0, len(order))
	for _, key := range order {
		g := groups[key]
		others := make([]pdns.RRset, 0, len(order)-1)
		for _, k := range order {
			if k != key {
				others = append(others, pdns.RRset{Name: groups[k].in.Name, Type: groups[k].in.Type})
			}
		}
		rr, err := l.RecordSet(z, g.in, others)
		if err != nil {
			return nil, indexed(g.first, err)
		}
		rr.Comments = nil // a new zone has no comments to clear
		out = append(out, rr)
	}
	return out, nil
}

// indexed prefixes a validation error with the template record index.
func indexed(i int, err error) error {
	var re *validate.RecordError
	if errors.As(err, &re) {
		field := re.Field
		if strings.HasPrefix(field, "values[") {
			field = "content"
		}
		return recordErr(i, field, re.Msg)
	}
	if errors.Is(err, validate.ErrName) {
		return recordErr(i, "name", strings.TrimPrefix(err.Error(), validate.ErrName.Error()+": "))
	}
	return err
}
