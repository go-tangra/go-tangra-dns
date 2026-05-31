package server

import (
	"io/fs"
	"net/http"
	"os"

	kratosHttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-dns/cmd/server/assets"
)

// NewHTTPServer creates an HTTP server for serving registration assets
// (openapi/descriptor/menus) and the embedded Module Federation frontend.
// REST traffic itself is transcoded to gRPC by the admin gateway.
func NewHTTPServer(ctx *bootstrap.Context) *kratosHttp.Server {
	l := ctx.NewLoggerHelper("dns/http")

	addr := os.Getenv("DNS_HTTP_ADDR")
	if addr == "" {
		addr = "0.0.0.0:9801"
	}

	srv := kratosHttp.NewServer(kratosHttp.Address(addr))

	route := srv.Route("/")
	route.GET("/health", func(ctx kratosHttp.Context) error {
		return ctx.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	route.GET("/openapi.yaml", func(ctx kratosHttp.Context) error {
		ctx.Response().Header().Set("Content-Type", "application/yaml")
		_, err := ctx.Response().Write(assets.OpenApiData)
		return err
	})

	route.GET("/proto-descriptor", func(ctx kratosHttp.Context) error {
		ctx.Response().Header().Set("Content-Type", "application/octet-stream")
		ctx.Response().Header().Set("Content-Disposition", "attachment; filename=descriptor.bin")
		_, err := ctx.Response().Write(assets.DescriptorData)
		return err
	})

	route.GET("/menus.yaml", func(ctx kratosHttp.Context) error {
		ctx.Response().Header().Set("Content-Type", "application/yaml")
		_, err := ctx.Response().Write(assets.MenusData)
		return err
	})

	fsys, err := fs.Sub(assets.FrontendDist, "frontend-dist")
	if err == nil {
		fileServer := http.FileServer(http.FS(fsys))
		srv.HandlePrefix("/", fileServer)
		l.Infof("Serving embedded frontend assets")
	} else {
		l.Warnf("Failed to load embedded frontend assets: %v", err)
	}

	l.Infof("HTTP server listening on %s", addr)
	return srv
}
