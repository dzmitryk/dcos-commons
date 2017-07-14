import pytest

import sdk_versions

from tests.config import (
    PACKAGE_NAME,
    DEFAULT_TASK_COUNT
)

@pytest.mark.upgrade
@pytest.mark.sanity
def test_upgrade():
    sdk_versions.upgrade(PACKAGE_NAME, PACKAGE_NAME, DEFAULT_TASK_COUNT, reinstall_test_version=False)


@pytest.mark.downgrade
@pytest.mark.sanity
def test_downgrade():
    sdk_versions.downgrade(PACKAGE_NAME, PACKAGE_NAME, DEFAULT_TASK_COUNT, reinstall_test_version=False)

