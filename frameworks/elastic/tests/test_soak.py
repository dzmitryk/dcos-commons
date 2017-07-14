import json
import pytest
import sdk_versions
from tests.config import (
    PACKAGE_NAME,
    DEFAULT_TASK_COUNT,
)


@pytest.mark.soak_upgrade
def test_soak_upgrade_downgrade():
    """ Assumes that the install options file is placed in the repo root directory by the user.
    """
    with open('elastic.json') as options_file:
        install_options = json.load(options_file)
    sdk_versions.soak_upgrade_downgrade(
            "beta-{}".format(PACKAGE_NAME),
            PACKAGE_NAME,
            PACKAGE_NAME,
            DEFAULT_TASK_COUNT,
            DEFAULT_ELASTIC_TIMEOUT,
            install_options)
