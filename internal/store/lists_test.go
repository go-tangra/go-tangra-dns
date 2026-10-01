package store

import "testing"

func TestListSpecsValid(t *testing.T) {
	for name, s := range map[string]interface{ Validate() error }{
		"zones": ZoneList, "records": RecordList, "templates": TemplateList, "supermasters": SupermasterList,
	} {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if RecordList.MaxSize != 200 {
		t.Errorf("records max page size = %d", RecordList.MaxSize)
	}
}
