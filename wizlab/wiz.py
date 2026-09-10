"""Author tools against the tenant: `wiz tenant|queries|type`, `audit user`."""
import sys

from . import core, session

# Schema-explorer spike: find the audit-log/activity query that could drive a reaper, and drill into
# its return type. Kept as general Wiz API exploration, not throwaway.
INTROSPECT_QUERIES = """query { __schema { queryType { fields {
  name
  args { name }
  type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
} } } }"""


# __type is inlined (Wiz's gateway won't bind $variables on introspection; normal queries bind fine).
INTROSPECT_TYPE = ('query { __type(name: "%s") { fields { name type { kind name ofType '
                   '{ kind name ofType { kind name } } } } inputFields { name } enumValues { name } } }')


def _typename(t):
    # Unwrap NON_NULL/LIST wrappers to the underlying named type.
    while t and not t.get("name") and t.get("ofType"):
        t = t["ofType"]
    return (t or {}).get("name") or "?"


def cmd_wiz_tenant(args):
    """Emit this tenant's connector facts as KEY=value, live from the Wiz API — no hardcoded
    per-tenant values. A script `eval`s stdout to feed a terraform apply (the Wiz connector-role
    module needs remote-arn + external-id). One call, one auth; grow it by adding keys (readers take
    only what they know). To $EXEC_OUTPUT too, for a note/HCL ref."""
    params, tid = _managed_identity()
    aws, gcp, azure = params["aws"], params["gcp"], params["azure"]
    facts = {
        "WIZ_REMOTE_ARN": aws.get("roleArn") or "",     # the delegator Wiz assumes (per-tenant/dc)
        "WIZ_EXTERNAL_ID": tid or "",                    # tenant id == the role's sts:ExternalId
        "WIZ_AWS_ENV": aws.get("defaultEnvironment") or "",
        # GCP's whole Wiz-side identity: the SA the vendor TF module takes as
        # wiz_managed_identity_external_id. Its prod-<dc> segment is per-tenant AND per-data-center,
        # so a lab must feed this live value to terraform, never commit a literal.
        "WIZ_GCP_SERVICE_ACCOUNT": gcp.get("serviceAccountEmail") or "",
        # Azure's Application (client) id. NOT the service-principal OBJECT id, which lives in the
        # customer's own directory and is unknowable to Wiz — that one is an operator secret.
        "WIZ_AZURE_APP_ID": ((azure.get("commercial") or {}).get("appId")) or "",
    }
    # Fatal only when the tenant yields NOTHING: a GCP-only lab must not die because this tenant has
    # no AWS managed identity, and vice versa. Callers assert the one key they need
    # (`: "${WIZ_GCP_SERVICE_ACCOUNT:?...}"`), which is also what "readers take only what they know"
    # requires — emitting a key is this verb's job, needing it is the script's.
    if not any(facts.values()):
        core.die(3, "managedIdentityParameters returned no usable tenant facts (no aws roleArn, no gcp SA, no tid)")
    core._emit("".join(f"{k}={v}\n" for k, v in facts.items() if v))


def cmd_wiz_queries(args):
    """List top-level Wiz queries whose name matches any --match term (default: audit-relevant), with
    return type. Finds the audit-log/activity query a reaper could use to enumerate what a user made."""
    terms = (core._flag(args, "--match") or "audit,activity,event,log,entit,delete").lower().split(",")
    data, _ = core.api(INTROSPECT_QUERIES, {})
    fields = ((data.get("__schema") or {}).get("queryType") or {}).get("fields") or []
    hits = [f for f in fields if any(t in f["name"].lower() for t in terms)]
    for f in sorted(hits, key=lambda f: f["name"]):
        argnames = ", ".join(a["name"] for a in (f.get("args") or []))
        print(f"{f['name']}({argnames}) -> {_typename(f.get('type'))}")
    print(f"# {len(hits)} match of {len(fields)} top-level queries", file=sys.stderr)


def cmd_wiz_type(args):
    """Print a Wiz type's fields / inputFields / enumValues (drill into a `wiz queries` return type)."""
    name = core._flag(args, "--name") or core.die(2, "wiz type needs --name <TypeName>")
    if not name.isidentifier():
        core.die(2, "type name must be alphanumeric")
    data, _ = core.api(INTROSPECT_TYPE % name, {})
    t = data.get("__type")
    if not t:
        core.die(1, f"no such type: {name}")
    for f in t.get("fields") or []:
        print(f"{f['name']}: {_typename(f.get('type'))}")
    for f in t.get("inputFields") or []:
        print(f"(in) {f['name']}")
    for v in t.get("enumValues") or []:
        print(f"(enum) {v['name']}")


def _audit_entries(send, minutes, mutations_only=True):
    """Every audit entry in the window, newest page first, via `send` (api or _gql). Returns (entries,
    alert). The filter is a literal: `minutes` is an int and MUTATION an enum, neither user text."""
    scope = "actionType: MUTATION, " if mutations_only else ""
    qy = ("query Audit($after: String) { auditLogEntries(first: 100, after: $after, filterBy: { " + scope
          + f"timestamp: {{ inLast: {{ amount: {int(minutes)}, unit: DurationFilterValueUnitMinutes }} }} }}) "
          "{ nodes { action actionType status timestamp performer { id name } actionParameters } "
          "pageInfo { hasNextPage endCursor } } }")
    entries, alert = core._paged(send, qy, {}, "auditLogEntries")
    return entries, (f"audit enumeration {alert}" if alert else None)


def cmd_audit_user(args):
    """Catch/backstop: list Wiz audit actions by the ephemeral lab user in a recent window. Enumerates
    everything a learner did (GUI creates included) — the reaper's detection layer. Default shows only
    MUTATION (state-changing); --all includes queries. Match by --email/--account, override --match."""
    match = core._flag(args, "--match")
    email = core._flag(args, "--email") or (None if match else core._lab_user_email(args)[0])
    needle = (match or email).lower()
    minutes = int(core._flag(args, "--last-min") or "120")
    include_all = "--all" in args
    entries, alert = _audit_entries(core._api_send, minutes, mutations_only=not include_all)
    hits = 0
    for n in entries:
        p = n.get("performer") or {}
        if needle in f"{p.get('id', '')} {p.get('name', '')}".lower():
            hits += 1
            print(f"{n['timestamp']}  {n['actionType']:10} {n.get('status', ''):8} {n['action']}")
    kind = "ALL" if include_all else "MUTATION"
    print(f"# {hits} {kind} action(s) by {email or match} in last {minutes}m", file=sys.stderr)
    if alert:
        core.die(3, f"{alert}; the list above is incomplete")


def _managed_identity():
    data, tid = core.api(session.IDENTITY, {})
    params = data.get("managedIdentityParameters") or {}
    return {"aws": params.get("aws") or {}, "gcp": params.get("gcp") or {}, "azure": params.get("azure") or {}}, tid
