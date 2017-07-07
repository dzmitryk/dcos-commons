import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID

import sdk_cmd as cmd
import sdk_install as install
import sdk_plan as plan
import sdk_tasks as tasks
import sdk_utils
import shakedown
from tests.config import (
    PACKAGE_NAME
)


DEFAULT_BACKEND = default_backend()


def setup_module(module):
    install.uninstall(PACKAGE_NAME)
    cmd.run_cli("package install --cli dcos-enterprise-cli")


def teardown_module(module):
    # TODO(mh): Improve me
    create_service_account('hello-world')
    install.uninstall(PACKAGE_NAME)
    delete_service_account('hello-world')


def create_service_account(name, secret_name=None):
    """
    Creates a service account, a secret containing private key and uid and
    assigns `superuser` permissions to the account.

    Args:
        name (str): Name of the user account
        secret_name (str): Optionally name of secret. If not provided service
            account name will be used.
    """
    if secret_name is None:
        secret_name = name

    cmd.run_cli(
        "security org service-accounts keypair private-key.pem public-key.pem")
    cmd.run_cli(
        'security org service-accounts create -p public-key.pem '
        '-d "My service account" {name}'.format(
            name=name)
        )
    cmd.run_cli(
        "security secrets create-sa-secret private-key.pem "
        "{name} {secret_name}".format(
            name=name,
            secret_name=secret_name)
        )
    # TODO(mh): Fine grained permissions needs to be addressed in DCOS-16475
    cmd.run_cli(
        "security org groups add_user superusers {name}".format(name=name))


def delete_service_account(name, secret_name=None):
    """
    Deletes service account and secret with private key that belongs to the
    service account.

    Args:
        name (str): Name of the user account
        secret_name (str): Optionally name of secret. If not provided service
            account name will be used.
    """
    if secret_name is None:
        secret_name = name

    cmd.run_cli(
        "security org service-accounts delete {name}".format(name=name))
    cmd.run_cli(
        "security secrets delete {secret_name}".format(secret_name=secret_name))


@pytest.fixture()
def service_account():
    """
    Creates service account with `hello-world` name and yields the name.
    """
    name = 'hello-world'
    create_service_account(name)
    yield name
    delete_service_account(name)


def test_tls_basics(service_account):
    install.install(
        PACKAGE_NAME,
        running_task_count=1,
        service_name=service_account,
        additional_options={
            "service": {
                "spec_file": "examples/tls.yml",
                "secret_name": service_account,
                "principal": service_account,
                },
            }
        )

    deployment_plan = plan.get_deployment_plan(PACKAGE_NAME)
    sdk_utils.out("deployment_plan: " + str(deployment_plan))

    # default is serial strategy, hello deploys first
    # launch will fail if secrets are not available or not accessible
    plan.wait_for_completed_deployment(PACKAGE_NAME)

    task_id = tasks.get_task_ids(PACKAGE_NAME, "tls")[0]
    assert task_id

    # Load end-entity certificate from keystore and root CA cert from truststore
    end_entity_cert = _export_cert_from_task_keystore(
        task_id, 'keystore.keystore', 'cert')

    root_ca_cert_in_truststore = _export_cert_from_task_keystore(
        task_id, 'keystore.truststore', 'dcos-root')

    # Check that certificate subject maches the service name
    common_name = end_entity_cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)[0].value
    assert common_name == PACKAGE_NAME

    sans = end_entity_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    cluster_root_ca_cert = x509.load_pem_x509_certificate(
        cmd.request(
            'get', shakedown.dcos_url_path('/ca/dcos-ca.crt')).content,
        DEFAULT_BACKEND)

    assert root_ca_cert_in_truststore.signature == cluster_root_ca_cert.signature

    install.uninstall(PACKAGE_NAME)


def task_exec(task_name, command):
    return cmd.run_cli(
        "task exec {} {}".format(task_name, command))


def _export_cert_from_task_keystore(
        task, keystore_path, alias):
    cert_bytes = task_exec(
        task, _keystore_export_command(keystore_path, alias, '-rfc')
    ).encode('ascii')

    return x509.load_pem_x509_certificate(
        cert_bytes, DEFAULT_BACKEND)


def _keystore_list_command(keystore_path, args=None):
    """
    Creates a command that can be executed using `dcos exec` CLI and will
    list certificates from provided keystore using java `keytool` command.

    https://docs.oracle.com/javase/8/docs/technotes/tools/windows/keytool.html

    Args:
        keystore_path (str): Path to the keystore file
        args (str): Optionally addiontal arguments for the `keytool -list`
            command.

    Returns:
        A string that can be used as `dcos exec` argument.
    """
    return _java_command(
        'keytool -list -keystore {keystore_path} '
        '-noprompt -storepass "" {args}'.format(
            keystore_path=keystore_path,
            args=args
        )
    )


def _keystore_export_command(keystore_path, cert_alias, args=None):
    return _java_command(
        'keytool -exportcert -keystore {keystore_path} '
        '-storepass "" -alias {alias} {args}'.format(
            keystore_path=keystore_path,
            alias=cert_alias,
            args=args
        )
    )


def _java_command(command):
    return (
        "bash -c ' "
        "export JAVA_HOME=$(ls -d $MESOS_SANDBOX/jre*/); "
        "export JAVA_HOME=${{JAVA_HOME%/}}; "
        "export PATH=$(ls -d $JAVA_HOME/bin):$PATH; "
        "{command}"
        "'"
    ).format(command=command)
