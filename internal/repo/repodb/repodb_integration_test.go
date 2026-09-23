//go:build integration

// Package repodb integration test: runs the repo conformance suite against a
// real TimescaleDB (testcontainers) and adds the checks only a database can
// make: migrations are idempotent, row-level security isolates two tenants even
// for raw SQL under the app role, the GLOBAL zone-name unique index refuses a
// second tenant's insert it cannot even see, dns_zone_conflict answers
// equal/ancestor/descendant/same-tenant with a boolean only, dns_zone_names
// returns names only, the supermaster (ip, nameserver) pair is global, and the
// composite (tenant_id, id) foreign key refuses cross-tenant challenge rows.
// Run with:
//
//	go test -tags integration ./internal/repo/repodb/
//
// It skips cleanly when Docker/testcontainers is unavailable. Set
// DNS_IT_ADMIN_DSN (a superuser DSN of an existing TimescaleDB server) to
// run against it instead: a throwaway database is created and dropped.
package repodb_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/repo/repodb"
	"github.com/go-freya/freya/services/dns/internal/repo/repotest"
	"github.com/go-freya/freya/services/dns/internal/store"
)

type dbEnv struct {
	adminDSN, appDSN string
}

// existingDB prepares a throwaway database on the server named by
// DNS_IT_ADMIN_DSN.
func existingDB(t *testing.T, admin string) dbEnv {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Skipf("DNS_IT_ADMIN_DSN unreachable: %v", err)
	}
	name := "dns_it_" + strings.ReplaceAll(store.NewID()[:13], "-", "")
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	var roleExists bool
	_ = conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dns_app')").Scan(&roleExists)
	if !roleExists {
		if _, err := conn.Exec(ctx, "CREATE ROLE dns_app LOGIN PASSWORD 'app' NOBYPASSRLS"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		if !roleExists {
			_, _ = conn.Exec(ctx, "DROP ROLE IF EXISTS dns_app")
		}
		_ = conn.Close(ctx)
	})
	adminCfg := cfg.Copy()
	adminCfg.Database = name
	host := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	env := dbEnv{
		adminDSN: fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", cfg.User, cfg.Password, host, name),
		appDSN:   "postgres://dns_app:app@" + host + "/" + name + "?sslmode=disable",
	}
	db, err := pgx.Connect(ctx, env.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS timescaledb"); err != nil {
		t.Skipf("timescaledb unavailable: %v", err)
	}
	_ = db.Close(ctx)
	if !roleExists {
		return env
	}
	t.Skip("role dns_app already exists on this server; refusing to reuse it")
	return env
}

func startDB(t *testing.T) dbEnv {
	t.Helper()
	ctx := context.Background()
	if admin := os.Getenv("DNS_IT_ADMIN_DSN"); admin != "" {
		env := existingDB(t, admin)
		if err := store.Migrate(ctx, env.adminDSN); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		if err := store.Migrate(ctx, env.adminDSN); err != nil {
			t.Fatalf("migrate idempotent: %v", err)
		}
		return env
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
			Env:        map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "dns"},
			WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		}, Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "5432/tcp")
	env := dbEnv{
		adminDSN: "postgres://postgres:test@" + host + ":" + port.Port() + "/dns?sslmode=disable",
		appDSN:   "postgres://dns_app:app@" + host + ":" + port.Port() + "/dns?sslmode=disable",
	}
	conn, err := pgx.Connect(ctx, env.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE ROLE dns_app LOGIN PASSWORD 'app' NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	if err := store.Migrate(ctx, env.adminDSN); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := store.Migrate(ctx, env.adminDSN); err != nil {
		t.Fatalf("migrate idempotent: %v", err)
	}
	return env
}

func TestRepoDB(t *testing.T) {
	env := startDB(t)
	ctx := context.Background()
	// One database for the whole suite: each case truncates first.
	st, err := store.Open(ctx, env.appDSN, 4)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(st.Close)
	db := repodb.New(st)
	admin, err := pgx.Connect(ctx, env.adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })
	truncate := func(t *testing.T) {
		t.Helper()
		if _, err := admin.Exec(ctx, `TRUNCATE dns_acme_challenges, dns_ipam_sync, dns_supermasters, dns_zone_templates, dns_zones, dns_server_config CASCADE`); err != nil {
			t.Fatal(err)
		}
	}
	app := func(t *testing.T) *pgx.Conn {
		t.Helper()
		conn, err := pgx.Connect(ctx, env.appDSN)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(ctx) })
		return conn
	}

	t.Run("conformance", func(t *testing.T) {
		repotest.Run(t, func(t *testing.T) repo.Store { truncate(t); return db })
	})

	t.Run("rls isolates raw sql", func(t *testing.T) {
		truncate(t)
		if err := db.CreateZone(ctx, repotest.NewZone(repotest.TenantA, "secret.example.")); err != nil {
			t.Fatal(err)
		}
		if err := db.CreateTemplate(ctx, store.Template{ID: store.NewID(), TenantID: repotest.TenantA, Name: "t"}); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"dns_zones", "dns_zone_templates"} {
			var n int
			err := st.Tx(ctx, store.Scope{TenantID: repotest.TenantB}, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n)
			})
			if err != nil || n != 0 {
				t.Fatalf("tenant B sees %d %s rows (%v)", n, table, err)
			}
		}
		// the app role outside any scope reads nothing
		var n int
		if err := app(t).QueryRow(ctx, `SELECT count(*) FROM dns_zones`).Scan(&n); err == nil && n != 0 {
			t.Fatalf("unscoped app role read %d zones", n)
		}
		// writing a row for another tenant under tenant B's scope is refused by WITH CHECK
		err := st.Tx(ctx, store.Scope{TenantID: repotest.TenantB}, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO dns_zone_templates (id, tenant_id, name) VALUES ($1, $2, 'x')`, store.NewID(), repotest.TenantA)
			return err
		})
		if err == nil {
			t.Fatal("cross-tenant insert admitted")
		}
	})

	t.Run("global zone name uniqueness under rls", func(t *testing.T) {
		truncate(t)
		if err := db.CreateZone(ctx, repotest.NewZone(repotest.TenantA, "example.com.")); err != nil {
			t.Fatal(err)
		}
		// tenant B cannot see A's zone, yet its insert of the same name fails
		if _, err := db.GetZoneByName(ctx, repotest.TenantB, "example.com."); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("B sees A's zone: %v", err)
		}
		z := repotest.NewZone(repotest.TenantB, "example.com.")
		z.PDNSID = "other-id"
		if err := db.CreateZone(ctx, z); !errors.Is(err, repo.ErrConflict) {
			t.Fatalf("duplicate across tenants: %v", err)
		}
		// the pdns_id is global too
		z2 := repotest.NewZone(repotest.TenantB, "other.example.")
		z2.PDNSID = "example.com."
		if err := db.CreateZone(ctx, z2); !errors.Is(err, repo.ErrConflict) {
			t.Fatalf("duplicate pdns id: %v", err)
		}
		// the table's CHECK refuses non-canonical names
		bad := repotest.NewZone(repotest.TenantA, "Example.ORG")
		if err := db.CreateZone(ctx, bad); err == nil {
			t.Fatal("non-canonical name admitted")
		}
	})

	t.Run("zone conflict function returns a boolean only", func(t *testing.T) {
		truncate(t)
		if err := db.CreateZone(ctx, repotest.NewZone(repotest.TenantA, "example.com.")); err != nil {
			t.Fatal(err)
		}
		conn := app(t)
		rows, err := conn.Query(ctx, `SELECT * FROM dns_zone_conflict('www.example.com.', $1::uuid)`, repotest.TenantB)
		if err != nil {
			t.Fatal(err)
		}
		cols := rows.FieldDescriptions()
		var got []bool
		for rows.Next() {
			var b bool
			if err := rows.Scan(&b); err != nil {
				t.Fatal(err)
			}
			got = append(got, b)
		}
		rows.Close()
		if len(cols) != 1 || len(got) != 1 || !got[0] {
			t.Fatalf("columns = %d, rows = %v", len(cols), got)
		}
		for name, want := range map[string]bool{"example.com.": true, "www.example.com.": true, "com.": true, "xexample.com.": false, "example.org.": false} {
			var b bool
			if err := conn.QueryRow(ctx, `SELECT dns_zone_conflict($1, $2::uuid)`, name, repotest.TenantB).Scan(&b); err != nil || b != want {
				t.Errorf("conflict(%s) = %v (%v), want %v", name, b, err, want)
			}
			if err := conn.QueryRow(ctx, `SELECT dns_zone_conflict($1, $2::uuid)`, name, repotest.TenantA).Scan(&b); err != nil || b {
				t.Errorf("same tenant %s = %v (%v)", name, b, err)
			}
		}
		// dns_zone_names returns one text column of names, callable by the app role
		nrows, err := conn.Query(ctx, `SELECT * FROM dns_zone_names()`)
		if err != nil {
			t.Fatal(err)
		}
		ncols := nrows.FieldDescriptions()
		nrows.Close()
		if len(ncols) != 1 {
			t.Fatalf("dns_zone_names columns = %d", len(ncols))
		}
	})

	t.Run("supermaster pair is global", func(t *testing.T) {
		truncate(t)
		sm := store.Supermaster{ID: store.NewID(), TenantID: repotest.TenantA, IP: "192.0.2.53", Nameserver: "ns1.example.net."}
		if err := db.CreateSupermaster(ctx, sm); err != nil {
			t.Fatal(err)
		}
		dup := store.Supermaster{ID: store.NewID(), TenantID: repotest.TenantB, IP: "192.0.2.53", Nameserver: "ns1.example.net."}
		if err := db.CreateSupermaster(ctx, dup); !errors.Is(err, repo.ErrConflict) {
			t.Fatalf("pair across tenants: %v", err)
		}
		if list, _ := db.ListSupermasters(ctx, repotest.TenantB); len(list) != 0 {
			t.Fatal("B sees A's supermaster")
		}
	})

	t.Run("composite keys refuse cross-tenant challenges", func(t *testing.T) {
		truncate(t)
		za := repotest.NewZone(repotest.TenantA, "example.com.")
		if err := db.CreateZone(ctx, za); err != nil {
			t.Fatal(err)
		}
		// even with the system scope (no RLS filter) the FK refuses B's row on A's zone
		err := st.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO dns_acme_challenges (id, tenant_id, zone_id, fqdn, value) VALUES ($1, $2, $3, '_acme-challenge.example.com.', 'v')`,
				store.NewID(), repotest.TenantB, za.ID)
			return err
		})
		if err == nil {
			t.Fatal("cross-tenant challenge admitted")
		}
		c := store.Challenge{ID: store.NewID(), TenantID: repotest.TenantB, ZoneID: za.ID, FQDN: "_acme-challenge.example.com.", Value: "v"}
		if err := db.InsertChallenge(ctx, c); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("cross-tenant challenge: %v", err)
		}
	})

	t.Run("malformed ids are not found", func(t *testing.T) {
		truncate(t)
		if _, err := db.GetZone(ctx, repotest.TenantA, "not-a-uuid"); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if _, err := db.GetTemplate(ctx, repotest.TenantA, "x"); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("template: %v", err)
		}
		if _, err := db.GetZone(ctx, "not-a-tenant", store.NewID()); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("tenant: %v", err)
		}
		if err := db.InsertChallenge(ctx, store.Challenge{TenantID: repotest.TenantA, ZoneID: "x"}); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("challenge zone: %v", err)
		}
		if err := db.ClearSyncZone(ctx, repotest.TenantA, "x"); err != nil {
			t.Fatal(err)
		}
	})
}
