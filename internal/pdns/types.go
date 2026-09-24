package pdns

// PowerDNS RRset change types (PATCH /zones/{id}).
const (
	ChangeReplace = "REPLACE"
	ChangeDelete  = "DELETE"
)

// Zone is the PowerDNS zone resource (the fields the module uses). Kind uses
// PowerDNS's spelling (Native|Master|Slave|Producer|Consumer). Serial and
// NotifiedSerial are read-only and never sent.
type Zone struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name"`
	Kind           string   `json:"kind,omitempty"`
	Serial         uint32   `json:"serial,omitempty"`
	NotifiedSerial uint32   `json:"notified_serial,omitempty"`
	Masters        []string `json:"masters,omitempty"`
	DNSSEC         bool     `json:"dnssec,omitempty"`
	Nameservers    []string `json:"nameservers,omitempty"`
	Account        string   `json:"account,omitempty"`
	RRsets         []RRset  `json:"rrsets,omitempty"`
}

// createBody is what POST /zones receives: the writable fields only.
type createBody struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Masters     []string `json:"masters,omitempty"`
	DNSSEC      bool     `json:"dnssec"`
	Nameservers []string `json:"nameservers"`
	Account     string   `json:"account,omitempty"`
	RRsets      []RRset  `json:"rrsets,omitempty"`
}

// metadataBody is what PUT /zones/{id} receives: kind, masters (always sent so
// switching away from slave clears them), dnssec and account.
type metadataBody struct {
	Kind    string   `json:"kind"`
	Masters []string `json:"masters"`
	DNSSEC  bool     `json:"dnssec"`
	Account string   `json:"account,omitempty"`
}

// RRset is a resource record set: name + type + ttl + N records (the API view
// of a spec "record set"). On REPLACE, a nil Comments keeps the rrset's
// existing comments while an empty non-nil list clears them (PowerDNS
// semantics; omitzero sends "comments": [] for the latter).
type RRset struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	TTL        uint32    `json:"ttl,omitempty"`
	ChangeType string    `json:"changetype,omitempty"`
	Records    []Record  `json:"records,omitempty"`
	Comments   []Comment `json:"comments,omitzero"`
}

// Record is one record content line within an RRset.
type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// Comment is a comment attached to an RRset.
type Comment struct {
	Content string `json:"content"`
	// Account is always sent: PowerDNS (4.9) refuses a comment without the
	// "account" key with 422, even when it is empty.
	Account    string `json:"account"`
	ModifiedAt int64  `json:"modified_at,omitempty"`
}

// Supermaster is an entry of the PowerDNS supermasters table.
type Supermaster struct {
	IP         string `json:"ip"`
	Nameserver string `json:"nameserver"`
	Account    string `json:"account,omitempty"`
}

type patchBody struct {
	RRsets []RRset `json:"rrsets"`
}

type zoneRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
