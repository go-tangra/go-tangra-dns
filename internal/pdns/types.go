package pdns

// Zone is the PowerDNS zone resource.
type Zone struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name"`
	Type           string   `json:"type,omitempty"`
	URL            string   `json:"url,omitempty"`
	Kind           string   `json:"kind,omitempty"`
	RRsets         []RRset  `json:"rrsets,omitempty"`
	Serial         uint32   `json:"serial,omitempty"`
	NotifiedSerial uint32   `json:"notified_serial,omitempty"`
	Masters        []string `json:"masters,omitempty"`
	DNSSEC         bool     `json:"dnssec,omitempty"`
	Nameservers    []string `json:"nameservers,omitempty"`
	Account        string   `json:"account,omitempty"`
}

// RRset is a resource record set: name + type + ttl + N records.
type RRset struct {
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	TTL        uint32         `json:"ttl,omitempty"`
	ChangeType string         `json:"changetype,omitempty"`
	Records    []RRsetRecord  `json:"records,omitempty"`
	Comments   []RRsetComment `json:"comments,omitempty"`
}

// RRsetRecord is a single record content line within an RRset.
type RRsetRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// RRsetComment is a comment attached to an RRset.
type RRsetComment struct {
	Content    string `json:"content"`
	Account    string `json:"account,omitempty"`
	ModifiedAt int64  `json:"modified_at,omitempty"`
}

// Supermaster represents an entry in the supermasters table.
type Supermaster struct {
	IP         string `json:"ip"`
	Nameserver string `json:"nameserver"`
	Account    string `json:"account,omitempty"`
}

// RRsetsPatch is the payload for the PATCH /zones/{id} endpoint.
type RRsetsPatch struct {
	RRsets []RRset `json:"rrsets"`
}
