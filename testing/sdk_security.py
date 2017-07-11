import shakedown
import skd_utils as utils


def create_and_assign_permission(dcosurl, token, role, account, description, action="create"):
    create_role_cmd = """curl -k -L -X PUT -H 'Authorization: token={token}'
        -d '{"description":"{description}}"}'
        -H 'Content-Type: application/json'
        -s {dcosurl}/acs/api/v1/acls/{role}""".format(
            token=token,
            description=description,
            dcosurl=dcosurl,
            role=role
        ).replace("\n", "")

    assign_to_role_cmd = """curl -k -L -X PUT -H 'Authorization: token={token}'
        -s {dcosurl}/acs/api/v1/acls/{role}/users/{account}/{action}""".format(
            token=token,
            dcosurl=dcosurl,
            role=role,
            account=account,
            action=action
        ).replace("\n", "")

    _, output = shakedown.run_command_on_agent(host, create_role_cmd)
    _, output = shakedown.run_command_on_agent(host, assign_to_role_cmd)


def grant_registration(dcosurl, token, role, account):
    utils.out("Authorizing {account} to register as a Mesos framework with role={role}".format(
        account=account,
        role=role
    ))
    fq_role = "dcos:mesos:master:framework:role:{role}".format(role=role)
    description = "Register with the Mesos master with role={role}".format(role=role)
    create_and_assign_permission(dcosurl, token, fq_role, account, description)


def grant_task_execution(dcosurl, token, role, account):
    utils.out("Authorizing {account} to execute Mesos tasks as user={role}".format(
        account=account,
        role=role
    ))

    fq_role = "dcos:mesos:master:task:user:{role}".format(role=role)
    description = "Execute Mesos tasks as user={role}".format(role=role)
    create_and_assign_permission(dcosurl, token, fq_role, account, description)

    # XXX 1.10 curerrently requires this mesos:agent permission as well as
    # mesos:task permission.  unclear if this will be ongoing requirement.
    # See DCOS-15682
    fq_role = "dcos:mesos:agent:task:user:{role}".format(role=role)
    description = "Execute Mesos tasks as user={role}".format(role=role)
    create_and_assign_permission(dcosurl, token, fq_role, account, description)

    # In order for the Spark Dispatcher to register with Mesos as
    # root, we must launch the dispatcher task as root.  The other
    # frameworks are launched as nobody, but then register as
    # service.user, which defaults to root
    utils.out("Authorizing dcos_marathon to execute Mesos tasks as root")
    fq_role = "dcos:mesos:master:task:user:root"
    description = "Execute Mesos tasks as user=root"
    create_and_assign_permission(dcosurl, token, fq_role, "dcos_marathon", description)

    # XXX see above
    fq_role = "dcos:mesos:agent:task:user:root"
    description = "Execute Mesos tasks as user=root"
    create_and_assign_permission(dcosurl, token, fq_role, "dcos_marathon", description)


def grant_resources(dcosurl, token, role, account):
    utils.out("Authorizing {account} to reserve Mesos resources with role={role}".format(
        account=account,
        role=role
    ))
    fq_role = "dcos:mesos:master:reservation:role:{role}".format(role=role)
    description = "Reserve Mesos resources with role={role}".format(role=role)
    create_and_assign_permission(dcosurl, token, fq_role, account, description)

    utils.out("Authorizing {account} to unreserve Mesos resources with principal={account}".format(
        account=account
    ))
    fq_role = "dcos:mesos:master:reservation:principal:{role}".format(role=account)
    description = "Reserve Mesos resources with principal={role}".format(role=account)
    create_and_assign_permission(dcosurl, token, fq_role, account, description, action="delete")


def grant_volumes(dcosurl, token, role, account):
    utils.out("Authorizing {account} to create Mesos volumes with role={role}".format(
        account=account,
        role=role
    ))
    fq_role = "dcos:mesos:master:volume:role:{role}".format(role=role)
    description = "Create Mesos volumes with role={role}".format(role=role)
    create_and_assign_permission(dcosurl, token, fq_role, account, description)

    utils.out("Authorizing {account} to delete Mesos volumes with principal={account}".format(
        account=account
    ))
    fq_role = "dcos:mesos:master:volume:principal:{role}".format(role=account)
    description = "Create Mesos volumes with principal={role}".format(role=account)
    create_and_assign_permission(dcosurl, token, fq_role, account, description, action="delete")


def grant_all(dcosurl, token, role, account):
    utils.out("Granting permissions to {account}...".format(account=account))
    grant_registration(dcosurl, token, role, account)
    grant_task_execution(dcosurl, token, role, account)
    grant_resources(dcosurl, token, role, account)
    grant_volumes(dcosurl, token, role, account)
    utils.out("Permission setup completed for {account}".format(account=account))


def create_service_account(account, secret_name):
    utils.out('Creating service account for account={account} secret={secret_name}'.format(
        account=account,
        secret_name=secret_name
    ))

    utils.out('Install cli necessary for security')
    install_enterprise_cli_cmd = 'package install dcos-enterprise-cli --package-version=1.0.7'
    out, err, rc = shakedown.run_dcos_command(install_enterprise_cli_cmd)
    if not rc:
        raise Exception('Failed to install dcos-enterprise cli extension')

    utils.out('Create keypair')
    create_keypair_cmd = 'security org service-accounts keypair private-key.pem public-key.pem'
    out, err, rc = shakedown.run_dcos_command(create_keypair_cmd)
    if not rc:
        raise Exception('Failed to create keypair for testing service account')

    utils.out('Create service account')
    delete_account_cmd = 'security org service-accounts delete "{account}"'.format(account=account)
    out, err, rc = shakedown.run_dcos_command(delete_account_cmd)
    create_account_cmd = 'security org service-accounts create -p public-key.pem -d "My service account" "{account}"'.
        format(account=account)
    out, err, rc = shakedown.run_dcos_command(create_account_cmd)
    if not rc:
        raise Exception('Failed to create service account "{account}"'.format(account=account))

    utils.out('Create secret')
    delete_secret_cmd = 'security secrets delete "{secret_name}"'.format(secret_name=secret_name)
    out, err, rc = shakedown.run_dcos_command(delete_secret_cmd)
    create_secret_cmd = 'dcos security secrets create-sa-secret --strict private-key.pem "{account}" "{secret_name}"'.
        format(account=account, secret_name=secret_name)
    out, err, rc = shakedown.run_dcos_command(create_secret_cmd)
    if not rc:
        raise Exception('Failed to create secret "{secret_name}" for service account "{account}"'.format(
            account=account,
            secret_name=secret_name
        ))

    utils.out('Service account created for account={account} secret={secret_name}'.format(
        account=account,
        secret_name=secret_name
    ))


def configure_security(role, account='service-acct', secret_name='secret'):

    # TODO (kwood): what should these *really* be?
    dcosurl = "http://localhost:61001"
    token, _, _ = shakedown.run_dcos_command('config show core.dcos_acs_token')
    token = auth_token.strip()

    create_service_account(account, secret_name)
    gran_all(dcosurl, token, role, account)
