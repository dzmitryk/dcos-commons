import pytest

import sdk_versions
from tests.config import *


@pytest.mark.skip(reason="https://jira.mesosphere.com/browse/INFINITY-1933")
@pytest.mark.upgrade
@pytest.mark.sanity
def test_upgrade():
    sdk_versions.upgrade(
        "beta-{}".format(PACKAGE_NAME),
        PACKAGE_NAME,
        DEFAULT_TASK_COUNT,
        additional_options={"service": {"beta-optin": True}},
        reinstall_test_version=False)


@pytest.mark.skip(reason="https://jira.mesosphere.com/browse/INFINITY-1933")
@pytest.mark.downgrade
@pytest.mark.sanity
def test_downgrade():
    sdk_versions.downgrade(
        "beta-{}".format(PACKAGE_NAME),
        PACKAGE_NAME,
        DEFAULT_TASK_COUNT,
        additional_options={"service": {"beta-optin": True}},
        reinstall_test_version=False)

