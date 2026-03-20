package main

import "expvar"

var (
	// metricSessions counts KCP sessions accepted since startup.
	metricSessions = expvar.NewInt("sessions_total")
	// metricActiveSessions is the current number of open KCP sessions.
	metricActiveSessions = expvar.NewInt("sessions_active")
	// metricQueries counts DNS queries received since startup.
	metricQueries = expvar.NewInt("queries_total")
	// metricRateLimited counts queries dropped by the per-client rate limiter.
	metricRateLimited = expvar.NewInt("queries_rate_limited")
	// metricDropped counts oversized outgoing packets dropped in sendLoop.
	metricDropped = expvar.NewInt("packets_dropped")
)
