import pytest

from packlier import generate_paillier_keypair


@pytest.fixture(scope="session")
def keys():
    return generate_paillier_keypair(256)
