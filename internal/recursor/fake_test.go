package recursor

import (
	"errors"
	"strings"
	"testing"
)

func TestFake(t *testing.T) {
	var off Fake
	if off.Enabled() || off.SyncForward(ctx, "a.") != nil || off.RemoveForward(ctx, "a.") != nil || off.Ready(ctx) != nil {
		t.Fatal("zero fake must be a disabled no-op")
	}
	if l, err := off.ListForwards(ctx); l != nil || err != nil {
		t.Fatal("disabled list")
	}
	f := NewFake()
	if !f.Enabled() {
		t.Fatal("enabled")
	}
	if err := f.SyncForward(ctx, "Example.COM"); err != nil {
		t.Fatal(err)
	}
	f.Seed("Stale.example.", "10.0.0.1:53")
	if l, _ := f.ListForwards(ctx); strings.Join(l, ",") != "example.com.,stale.example." {
		t.Fatalf("list = %v", l)
	}
	if f.Forwards()["example.com."] != "172.20.0.5:53" {
		t.Fatal("target")
	}
	if err := f.RemoveForward(ctx, "stale.example"); err != nil || len(f.Forwards()) != 1 {
		t.Fatal("remove")
	}
	if err := f.RemoveForward(ctx, "absent."); err != nil {
		t.Fatal("absent remove must succeed")
	}
	if f.SyncForward(ctx, "") == nil || f.RemoveForward(ctx, ".") == nil {
		t.Fatal("empty names accepted")
	}
	boom := errors.New("boom")
	f.FailNext("SyncForward", boom)
	if err := f.SyncForward(ctx, "a."); !errors.Is(err, boom) {
		t.Fatal("injected")
	}
	f.SetReady(false)
	if err := f.Ready(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("not ready")
	}
	f.SetReady(true)
	if err := f.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	f.SetDown(true)
	for _, err := range []error{f.SyncForward(ctx, "a."), f.RemoveForward(ctx, "a."), f.Ready(ctx),
		func() error { _, err := f.ListForwards(ctx); return err }()} {
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("down: %v", err)
		}
	}
	if log := f.CallLog(); log[0] != "SyncForward example.com." {
		t.Fatalf("log = %v", log)
	}
	if (&StatusError{Status: 400, Message: "x"}).Unwrap() != nil || !errors.Is(&StatusError{Status: 502}, ErrUnavailable) {
		t.Fatal("status error unwrap")
	}
}
