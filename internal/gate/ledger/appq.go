package ledger

import "strings"

// Lifecycle rows record a change of an app tenancy on the phone, not a request (og-os M12c): its
// egress_kind names the event, kind is "other", method is empty and nothing left the phone (content
// and blocked false). region_id is "appq:<name>", adapter "appq", account_id the account it was
// added for, destination the app endpoints' host, class "outgate", app_id and participant its app
// and participant. path_class is the request's that caused it (the store rule's route, or the
// refused request for appq.revoked), status that request's (0 for none). Never the token or the
// package. They don't count in today's totals and don't go to OG Core's egress table.
const (
	AppqAdded    = "appq.added"    // sealed: kept from global's response (a store rule) or imported
	AppqRemoved  = "appq.removed"  // removed on the phone (appq_remove)
	AppqRevoked  = "appq.revoked"  // its token refused (401) by the app's endpoints: revoked on the web
	AppqMigrated = "appq.migrated" // a plain DE package of the bring-up, sealed and deleted
)

// Lifecycle reports whether r is a lifecycle row.
func Lifecycle(r *Row) bool {
	return r.Method == "" && strings.HasPrefix(r.EgressKind, "appq.")
}
