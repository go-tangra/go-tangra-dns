package pdns

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Fake is an in-memory PowerDNS Authoritative server for offline tests: zones
// with SOA/NS created like PowerDNS does, rrset REPLACE/DELETE semantics with a
// serial bump per change, NOTIFY limited to master/producer zones, BIND export
// rendering, supermasters, a call log and failure injection. It is safe for
// concurrent use.
type Fake struct {
	mu           sync.Mutex
	zones        map[string]*Zone
	supermasters []Supermaster
	failNext     map[string]error
	// Down makes every call fail with ErrUnavailable.
	Down bool
	// Calls logs "Op id" for every call (ownership assertions).
	Calls []string
}

var _ Client = (*Fake)(nil)

// NewFake builds an empty fake server.
func NewFake() *Fake {
	return &Fake{zones: map[string]*Zone{}, failNext: map[string]error{}}
}

// FailNext makes the next call of op (e.g. "CreateZone") return err.
func (f *Fake) FailNext(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[op] = err
}

// SetDown toggles the unreachable state.
func (f *Fake) SetDown(down bool) {
	f.mu.Lock()
	f.Down = down
	f.mu.Unlock()
}

// CallLog returns a copy of the call log.
func (f *Fake) CallLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Calls...)
}

// begin logs the call and returns an injected failure. Callers hold mu.
func (f *Fake) begin(op, id string) error {
	f.Calls = append(f.Calls, strings.TrimSpace(op+" "+id))
	if f.Down {
		return fmt.Errorf("%w: fake is down", ErrUnavailable)
	}
	if err, ok := f.failNext[op]; ok {
		delete(f.failNext, op)
		return err
	}
	return nil
}

func notFound(what string) error {
	return &APIError{Status: http.StatusNotFound, Message: "Could not find " + what, kind: ErrNotFound}
}

func unprocessable(msg string) error {
	return &APIError{Status: http.StatusUnprocessableEntity, Message: msg}
}

func cloneRRsets(in []RRset) []RRset {
	out := make([]RRset, len(in))
	for i, r := range in {
		r.Records = append([]Record(nil), r.Records...)
		r.Comments = append([]Comment(nil), r.Comments...)
		out[i] = r
	}
	return out
}

func cloneZone(z *Zone) Zone {
	c := *z
	c.Masters = append([]string(nil), z.Masters...)
	c.Nameservers = append([]string(nil), z.Nameservers...)
	c.RRsets = cloneRRsets(z.RRsets)
	return c
}

func (f *Fake) zone(id string) (*Zone, error) {
	z, ok := f.zones[id]
	if !ok {
		return nil, notFound("domain '" + id + "'")
	}
	return z, nil
}

func inZone(name, zone string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }

// Ping implements Client.
func (f *Fake) Ping(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.begin("Ping", "")
}

// ListZoneNames implements Client.
func (f *Fake) ListZoneNames(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("ListZoneNames", ""); err != nil {
		return nil, err
	}
	out := []string{}
	for _, z := range f.zones {
		out = append(out, z.Name)
	}
	sort.Strings(out)
	return out, nil
}

// GetZone implements Client.
func (f *Fake) GetZone(_ context.Context, id string) (Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("GetZone", id); err != nil {
		return Zone{}, err
	}
	z, err := f.zone(id)
	if err != nil {
		return Zone{}, err
	}
	return cloneZone(z), nil
}

// CreateZone implements Client: the id is the name; SOA and NS rrsets are
// generated from the nameservers (PowerDNS behaviour); initial rrsets are added.
func (f *Fake) CreateZone(_ context.Context, in Zone) (Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("CreateZone", in.Name); err != nil {
		return Zone{}, err
	}
	if in.Name == "" || !strings.HasSuffix(in.Name, ".") {
		return Zone{}, unprocessable("DNS Name '" + in.Name + "' is not canonical")
	}
	if _, dup := f.zones[in.Name]; dup {
		return Zone{}, &APIError{Status: http.StatusConflict, Message: "Domain '" + in.Name + "' already exists", kind: ErrConflict}
	}
	z := Zone{ID: in.Name, Name: in.Name, Kind: in.Kind, Serial: 1, Masters: append([]string(nil), in.Masters...),
		DNSSEC: in.DNSSEC, Nameservers: append([]string(nil), in.Nameservers...), Account: in.Account}
	if z.Kind == "" {
		z.Kind = "Native"
	}
	primary := "a.misconfigured.dns.server.invalid."
	if len(in.Nameservers) > 0 {
		primary = in.Nameservers[0]
	}
	z.RRsets = []RRset{{Name: z.Name, Type: "SOA", TTL: 3600, Records: []Record{{Content: primary + " hostmaster." + z.Name + " 1 10800 3600 604800 3600"}}}}
	if len(in.Nameservers) > 0 {
		ns := RRset{Name: z.Name, Type: "NS", TTL: 3600}
		for _, n := range in.Nameservers {
			ns.Records = append(ns.Records, Record{Content: n})
		}
		z.RRsets = append(z.RRsets, ns)
	}
	for _, r := range in.RRsets {
		if len(in.Nameservers) > 0 && r.Name == z.Name && r.Type == "NS" {
			return Zone{}, unprocessable("Nameservers list MUST NOT be mixed with zone-level NS in rrsets")
		}
		if !inZone(r.Name, z.Name) {
			return Zone{}, unprocessable("RRset " + r.Name + " IN " + r.Type + ": Name is out of zone")
		}
		r.ChangeType = ""
		z.RRsets = replaceRRset(z.RRsets, r)
	}
	f.zones[z.ID] = &z
	return cloneZone(&z), nil
}

func replaceRRset(sets []RRset, r RRset) []RRset {
	r = cloneRRsets([]RRset{r})[0]
	for i := range sets {
		if sets[i].Name == r.Name && sets[i].Type == r.Type {
			sets[i] = r
			return sets
		}
	}
	return append(sets, r)
}

// UpdateZoneMetadata implements Client.
func (f *Fake) UpdateZoneMetadata(_ context.Context, id string, in Zone) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("UpdateZoneMetadata", id); err != nil {
		return err
	}
	z, err := f.zone(id)
	if err != nil {
		return err
	}
	if in.Kind != "" {
		z.Kind = in.Kind
	}
	z.Masters = append([]string(nil), in.Masters...)
	z.DNSSEC = in.DNSSEC
	if in.Account != "" {
		z.Account = in.Account
	}
	return nil
}

// DeleteZone implements Client.
func (f *Fake) DeleteZone(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("DeleteZone", id); err != nil {
		return err
	}
	if _, err := f.zone(id); err != nil {
		return err
	}
	delete(f.zones, id)
	return nil
}

// PatchRRsets implements Client: REPLACE sets (name, type) to exactly the
// given records (an empty record list deletes it), DELETE removes it; the whole
// patch is refused (nothing applied) when any rrset is out of zone or carries
// an unknown change type. The serial is bumped once per applied patch.
func (f *Fake) PatchRRsets(_ context.Context, id string, rrsets []RRset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("PatchRRsets", id); err != nil {
		return err
	}
	z, err := f.zone(id)
	if err != nil {
		return err
	}
	for _, r := range rrsets {
		if !inZone(r.Name, z.Name) {
			return unprocessable("RRset " + r.Name + " IN " + r.Type + ": Name is out of zone")
		}
		if r.ChangeType != ChangeReplace && r.ChangeType != ChangeDelete {
			return unprocessable("changetype must be REPLACE or DELETE")
		}
		if r.Type == "SOA" && r.ChangeType == ChangeDelete {
			return unprocessable("SOA cannot be deleted")
		}
	}
	sets := cloneRRsets(z.RRsets)
	for _, r := range rrsets {
		kept := sets[:0]
		for _, s := range sets {
			if !(s.Name == r.Name && s.Type == r.Type) {
				kept = append(kept, s)
			}
		}
		if r.ChangeType == ChangeReplace && len(r.Records) > 0 && r.Comments == nil {
			r.Comments = commentsOf(sets, r.Name, r.Type) // nil keeps the existing comments
		}
		sets = kept
		if r.ChangeType == ChangeReplace && len(r.Records) > 0 {
			r.ChangeType = ""
			sets = append(sets, cloneRRsets([]RRset{r})[0])
		}
	}
	z.RRsets = sets
	z.Serial++
	return nil
}

func commentsOf(sets []RRset, name, typ string) []Comment {
	for _, s := range sets {
		if s.Name == name && s.Type == typ {
			return append([]Comment(nil), s.Comments...)
		}
	}
	return nil
}

// NotifyZone implements Client (PowerDNS refuses non-primary kinds).
func (f *Fake) NotifyZone(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("NotifyZone", id); err != nil {
		return err
	}
	z, err := f.zone(id)
	if err != nil {
		return err
	}
	if k := strings.ToLower(z.Kind); k != "master" && k != "producer" {
		return unprocessable("Domain is not a master or producer zone")
	}
	z.NotifiedSerial = z.Serial
	return nil
}

// ExportZone implements Client: one "name TTL IN type content" line per
// enabled record, SOA first, then sorted by name and type.
func (f *Fake) ExportZone(_ context.Context, id string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("ExportZone", id); err != nil {
		return "", err
	}
	z, err := f.zone(id)
	if err != nil {
		return "", err
	}
	sets := cloneRRsets(z.RRsets)
	sort.SliceStable(sets, func(i, j int) bool {
		if (sets[i].Type == "SOA") != (sets[j].Type == "SOA") {
			return sets[i].Type == "SOA"
		}
		if sets[i].Name != sets[j].Name {
			return sets[i].Name < sets[j].Name
		}
		return sets[i].Type < sets[j].Type
	})
	var b strings.Builder
	for _, s := range sets {
		for _, r := range s.Records {
			if r.Disabled {
				continue
			}
			fmt.Fprintf(&b, "%s\t%d\tIN\t%s\t%s\n", s.Name, s.TTL, s.Type, r.Content)
		}
	}
	return b.String(), nil
}

// ListSupermasters implements Client.
func (f *Fake) ListSupermasters(context.Context) ([]Supermaster, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("ListSupermasters", ""); err != nil {
		return nil, err
	}
	return append([]Supermaster{}, f.supermasters...), nil
}

// CreateSupermaster implements Client ((ip, nameserver) is unique).
func (f *Fake) CreateSupermaster(_ context.Context, s Supermaster) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("CreateSupermaster", s.IP+"/"+s.Nameserver); err != nil {
		return err
	}
	for _, x := range f.supermasters {
		if x.IP == s.IP && x.Nameserver == s.Nameserver {
			return &APIError{Status: http.StatusConflict, Message: "Supermaster already exists", kind: ErrConflict}
		}
	}
	f.supermasters = append(f.supermasters, s)
	return nil
}

// DeleteSupermaster implements Client.
func (f *Fake) DeleteSupermaster(_ context.Context, ip, nameserver string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("DeleteSupermaster", ip+"/"+nameserver); err != nil {
		return err
	}
	for i, x := range f.supermasters {
		if x.IP == ip && x.Nameserver == nameserver {
			f.supermasters = append(f.supermasters[:i], f.supermasters[i+1:]...)
			return nil
		}
	}
	return notFound("supermaster " + ip + "/" + nameserver)
}

// GenerateZone builds a zone with n A rrsets plus SOA and NS (the 5,000-rrset
// performance fixture of SC-008).
func GenerateZone(name string, n int) Zone {
	z := Zone{ID: name, Name: name, Kind: "Native", Serial: 1, Nameservers: []string{"ns1." + name}}
	z.RRsets = append(z.RRsets,
		RRset{Name: name, Type: "SOA", TTL: 3600, Records: []Record{{Content: "ns1." + name + " hostmaster." + name + " 1 10800 3600 604800 3600"}}},
		RRset{Name: name, Type: "NS", TTL: 3600, Records: []Record{{Content: "ns1." + name}}})
	for i := 0; i < n; i++ {
		z.RRsets = append(z.RRsets, RRset{Name: fmt.Sprintf("host%05d.%s", i, name), Type: "A", TTL: 300,
			Records: []Record{{Content: fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)}}})
	}
	return z
}

// Seed stores z as is (tests: a zone created outside the platform, or a large
// generated zone).
func (f *Fake) Seed(z Zone) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if z.ID == "" {
		z.ID = z.Name
	}
	c := cloneZone(&z)
	f.zones[c.ID] = &c
}
