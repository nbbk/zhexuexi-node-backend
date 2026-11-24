// Package v2rayapi is the sing-box V2Ray API stats client, vendored
// from sing-box v1.14.4 (experimental/v2rayapi/stats.proto, generated
// stats.pb.go and stats_grpc.pb.go). Only the client side is used:
// the agent queries the sing-box stats service on loopback to read
// per-inbound and per-user traffic counters.
//
// One line differs from the upstream generated code: the gRPC
// service name in stats_grpc.pb.go is
// "v2ray.core.app.stats.command.StatsService", not the proto
// package's "experimental.v2rayapi.StatsService". sing-box's own
// stats.go overrides the name in init() ("v2ray.core.app.stats.
// command.StatsService"), and the server registers under that name,
// so a client built from the unpatched generated code gets
// "unknown service". The patch is a plain string replacement of
// the service name; the wire format is unchanged.
//
// Regenerating from the .proto reproduces the unpatched files; the
// patch must be re-applied afterwards (grep for
// "v2ray.core.app.stats.command.StatsService" to verify).
package v2rayapi
