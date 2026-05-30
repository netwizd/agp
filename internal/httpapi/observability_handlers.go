package httpapi

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not_ready",
			"db":     "unavailable",
		})
		return
	}
	if err := s.store.Ping(r.Context()); err != nil {
		s.logger.Error("readiness check failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not_ready",
			"db":     "error",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ready",
		"db":     "ok",
	})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	var builder strings.Builder
	builder.WriteString("# HELP agp_up Whether AGP HTTP process is serving requests.\n")
	builder.WriteString("# TYPE agp_up gauge\n")
	builder.WriteString("agp_up 1\n")
	builder.WriteString("# HELP agp_db_up Whether AGP can query its storage backend.\n")
	builder.WriteString("# TYPE agp_db_up gauge\n")
	if s.store == nil {
		builder.WriteString("agp_db_up 0\n")
		writeMetrics(w, builder.String())
		return
	}

	if err := s.store.Ping(r.Context()); err != nil {
		s.logger.Error("metrics storage query failed", "error", err)
		builder.WriteString("agp_db_up 0\n")
		writeMetrics(w, builder.String())
		return
	}
	builder.WriteString("agp_db_up 1\n")
	writeMetrics(w, builder.String())
}

func writeGauge(builder *strings.Builder, name string, help string, value int) {
	fmt.Fprintf(builder, "# HELP %s %s\n", name, help)
	fmt.Fprintf(builder, "# TYPE %s gauge\n", name)
	fmt.Fprintf(builder, "%s %d\n", name, value)
}

func writeMetrics(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}
