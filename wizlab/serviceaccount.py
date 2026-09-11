"""The `wizcli` credential, minted through a CLI deployment."""
import sys

from . import core

# --- Wiz CLI credential for `wizcli auth`, minted via a CLI DEPLOYMENT: createServiceAccount rejects
# type:CLI. The secret is returned once, so `ensure` is delete-then-mint. Lifecycle: SPEC.md. ---
CLI_DEPLOYMENTS_Q = """query CliDeployments($f: DeploymentFilters, $after: String) {
  deployments(first: 50, after: $after, filterBy: $f) { nodes { id name type } pageInfo { hasNextPage endCursor } }
}"""


CREATE_CLI_DEPLOYMENT = """mutation CreateCliDeployment($input: CreateCliDeploymentInput!) {
  createCliDeployment(input: $input) {
    clientSecret
    deployment { id name type object { ... on WizCLI { serviceAccount { name clientId } } } }
  }
}"""


def _cli_dep_name(args):
    return core._named(args, "-cli")


def _find_cli_deployment(name):
    """The WIZ_CLI deployment whose name matches exactly (search is substring, so filter to ==)."""
    nodes = core._all_nodes(CLI_DEPLOYMENTS_Q, {"f": {"type": ["WIZ_CLI"], "search": name}}, "deployments")
    return core._exact(nodes, name)


def _delete_cli_deployment(dep_id):
    core.api(core._delete_doc("deleteCliDeployment", "id"), {"id": dep_id})


def cmd_serviceaccount_ensure(args):
    """Mint the on-the-fly wizcli credential via a CLI deployment, emitting WIZ_CLIENT_ID /
    WIZ_CLIENT_SECRET (wizcli's own env-var names) to stdout and $EXEC_OUTPUT. The client secret is
    shown once, so this converges to ONE fresh deployment: any existing one on this name is deleted
    first, then a fresh one created. Solve/setup only — never a learner check (it prints a secret)."""
    name = _cli_dep_name(args)
    existing = _find_cli_deployment(name)
    if existing:
        _delete_cli_deployment(existing["id"])
    data, _ = core.api(CREATE_CLI_DEPLOYMENT, {"input": {"name": name, "projectIDs": [], "expiresAt": None}})
    payload = data.get("createCliDeployment") or {}
    dep = payload.get("deployment") or {}
    sa = (dep.get("object") or {}).get("serviceAccount") or {}
    cid, sec = sa.get("clientId"), payload.get("clientSecret")
    if not cid or not sec:
        core.die(3, "createCliDeployment returned no client credentials")
    core._emit(f"WIZ_CLIENT_ID={cid}\nWIZ_CLIENT_SECRET={sec}\n")
    print(f"created wiz cli deployment {name} ({dep.get('id')})", file=sys.stderr)


def cmd_serviceaccount_inspect(args):
    """Assert the session's Wiz CLI deployment exists (--require exists)."""
    name = _cli_dep_name(args)
    node = _find_cli_deployment(name)
    if not node:
        print(f"no wiz cli deployment named {name}")
        sys.exit(1)
    print(f"wiz cli deployment {node['name']} ({node['id']})")


def cmd_serviceaccount_delete(args):
    """Delete the session's Wiz CLI deployment, by --id or (default) the session-stem name. Deleting the
    deployment is also the only path to the SA it created — see _reap_service_account."""
    dep_id = args.id
    if not dep_id:
        name = _cli_dep_name(args)
        node = _find_cli_deployment(name)
        if not node:
            print(f"no wiz cli deployment named {name}; nothing to delete")
            return
        dep_id = node["id"]
    _delete_cli_deployment(dep_id)
    print(f"deleted wiz cli deployment {dep_id}")
