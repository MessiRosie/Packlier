import os

import pytest

os.environ["PACKLIER_AUTO_UPDATE"] = "off"

from packlier import generate_paillier_keypair


@pytest.fixture(scope="session")
def keys():
    return generate_paillier_keypair(256)
