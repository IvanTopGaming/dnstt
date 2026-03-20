package main

import "expvar"

var (
	// metricTLSReconnects counts DoT reconnection attempts.
	metricTLSReconnects = expvar.NewInt("tls_reconnects_total")
	// metricDoQReconnects counts DoQ reconnection attempts.
	metricDoQReconnects = expvar.NewInt("doq_reconnects_total")
)
