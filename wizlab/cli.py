"""The command line: verbs, the flags each reads, the exit-code contract, `--check`."""
import sys

from . import (
    codescan,
    connector,
    core,
    lease,
    outpost,
    reap,
    role,
    sensor,
    serviceaccount,
    session,
    user,
    wiz,
    workflow,
)

VERBS = {
    ("session", "verify"): session.cmd_session_verify,
    ("connector", "inspect"): connector.cmd_connector_inspect,
    ("connector", "ensure"): connector.cmd_connector_ensure,
    ("connector", "delete"): connector.cmd_connector_delete,
    ("instance", "inspect"): connector.cmd_instance_inspect,
    ("sensor", "ensure"): sensor.cmd_sensor_ensure,
    ("sensor", "delete"): sensor.cmd_sensor_delete,
    ("sensor", "inspect"): sensor.cmd_sensor_inspect,
    ("serviceaccount", "ensure"): serviceaccount.cmd_serviceaccount_ensure,
    ("serviceaccount", "inspect"): serviceaccount.cmd_serviceaccount_inspect,
    ("serviceaccount", "delete"): serviceaccount.cmd_serviceaccount_delete,
    ("code-scan", "inspect"): codescan.cmd_codescan_inspect,
    ("policy", "ensure"): codescan.cmd_policy_ensure,
    ("policy", "inspect"): codescan.cmd_policy_inspect,
    ("policy", "delete"): codescan.cmd_policy_delete,
    ("detection", "inspect"): sensor.cmd_detection_inspect,
    ("workflow", "inspect"): workflow.cmd_workflow_inspect,
    ("workflow", "ensure"): workflow.cmd_workflow_ensure,
    ("workflow-run", "inspect"): workflow.cmd_workflowrun_inspect,
    ("workflow-run", "ensure"): workflow.cmd_workflowrun_ensure,
    ("outpost", "inspect"): outpost.cmd_outpost_inspect,
    ("outpost", "ensure"): outpost.cmd_outpost_ensure,
    ("outpost", "delete"): outpost.cmd_outpost_delete,
    ("role", "inspect"): role.cmd_role_inspect,
    ("role", "ensure"): role.cmd_role_ensure,
    ("user", "ensure"): user.cmd_user_ensure,
    ("user", "inspect"): user.cmd_user_inspect,
    ("user", "delete"): user.cmd_user_delete,
    ("user", "login-url"): user.cmd_user_login_url,
    ("wiz", "tenant"): wiz.cmd_wiz_tenant,
    ("wiz", "queries"): wiz.cmd_wiz_queries,
    ("wiz", "type"): wiz.cmd_wiz_type,
    ("audit", "user"): wiz.cmd_audit_user,
    ("user", "reap"): reap.cmd_reap,
    ("lease", "verify"): lease.cmd_lease_verify,
    ("lease", "ensure"): lease.cmd_lease_ensure,
    ("lease", "inspect"): lease.cmd_lease_inspect,
    ("lease", "delete"): lease.cmd_lease_delete,
}


# Every flag a verb reads, itself or through a helper. main() refuses anything else with exit 2: a
# misspelled flag used to be ignored, so a check graded on the default it meant to override.
_S = {"--session"}


_U = _S | {"--domain"}


FLAGS = {
    ("session", "verify"): {"--account-id", "--cloud", "--min-runner"},
    ("connector", "inspect"): _S | {"--account-id", "--cloud", "--outpost-id", "--outpost-name", "--require"},
    ("connector", "ensure"): _S | {"--account-id", "--cloud", "--outpost-id", "--outpost-name", "--role-arn",
                                   "--scanner-role-arn", "--tenant-id"},
    ("connector", "delete"): _S | {"--account-id", "--cloud"},
    ("instance", "inspect"): {"--account-id", "--type"},
    ("sensor", "ensure"): _S | {"--name"},
    ("sensor", "inspect"): _S | {"--name", "--require"},
    ("sensor", "delete"): _S | {"--id", "--name"},
    ("serviceaccount", "ensure"): _S | {"--name"},
    ("serviceaccount", "inspect"): _S | {"--name", "--require"},
    ("serviceaccount", "delete"): _S | {"--id", "--name"},
    ("code-scan", "inspect"): _S | {"--interval", "--require", "--tag-key", "--tag-value", "--timeout"},
    ("policy", "ensure"): {"--control-search", "--count-threshold", "--name", "--rule-id", "--severity"},
    ("policy", "inspect"): {"--name", "--require"},
    ("policy", "delete"): {"--name"},
    ("detection", "inspect"): _S | {"--match-only", "--name", "--rule-name", "--since-minutes"},
    ("workflow", "inspect"): _S | {"--exact-name", "--name", "--require"},
    ("workflow", "ensure"): _S | {"--definition", "--dry-run", "--exact-name", "--name", "--project-id"},
    ("workflow-run", "inspect"): _S | {"--branch", "--exact-name", "--name", "--require", "--run-type"},
    ("workflow-run", "ensure"): _S | {"--data", "--exact-name", "--initial-step", "--interval", "--name",
                                      "--timeout", "--trigger-type"},
    ("outpost", "inspect"): _S | {"--lookback-days", "--name", "--require"},
    ("outpost", "ensure"): _S | {"--name", "--region", "--role-arn"},
    ("outpost", "delete"): _S | {"--id", "--name", "--timeout"},
    ("role", "inspect"): {"--account-id", "--cloud", "--role-name"},
    ("role", "ensure"): {"--cloud", "--external-id", "--role-name"},
    ("user", "ensure"): _U | {"--group"},
    ("user", "inspect"): _U | {"--group"},
    ("user", "delete"): _U,
    ("user", "login-url"): set(),
    ("wiz", "tenant"): set(),
    ("wiz", "queries"): {"--match"},
    ("wiz", "type"): {"--name"},
    ("audit", "user"): _U | {"--all", "--email", "--last-min", "--match"},
    ("user", "reap"): _U | {"--commit", "--email", "--last-min"},
    ("lease", "verify"): set(),
    ("lease", "ensure"): {"--lab", "--timelimit-seconds"},
    ("lease", "inspect"): _S | {"--hostname", "--lab", "--require"},
    ("lease", "delete"): {"--key-id", "--lab"},
}


def _check_flags(verb, argv):
    unknown = [a for a in argv if a.startswith("--") and a not in FLAGS[verb]]
    if unknown:
        core.die(2, f"unknown flag {unknown[0]} for `wizlab {' '.join(verb)}`; "
               f"known: {' '.join(sorted(FLAGS[verb])) or '(none)'}")


def _run(argv):
    """Exit code for one invocation. One structural guard: any uncaught exception is a bug/invocation
    error (2), never a raw traceback exiting 1 (which a learner check would read as "you're wrong")."""
    try:
        if len(argv) < 2 or (argv[0], argv[1]) not in VERBS:
            core.die(2, f"usage: wizlab [--check] {{{' | '.join(' '.join(k) for k in VERBS)}}} [flags]")
        verb = (argv[0], argv[1])
        _check_flags(verb, argv[2:])
        VERBS[verb](argv[2:])
    except core.WizlabError as e:
        return core._fail(e)
    except SystemExit as e:
        return e.code or 0
    except Exception as e:
        return core._fail(core.WizlabError(2, f"internal error: {type(e).__name__}: {e}"))
    return 0


def main():
    argv = sys.argv[1:]
    if argv[:1] == ["--check"]:
        # The learner-check wrapper: anything but 0 is 1 (an out-of-list code puts the session in a
        # terminal `validating_error`), with the real code on stderr for the setup log.
        code = _run(argv[1:])
        if code:
            print(f"wizlab: exit {code}", file=sys.stderr)
            sys.exit(1)
        return
    code = _run(argv)
    if code:
        sys.exit(code)
