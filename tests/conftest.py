import pytest

from paillier_numpy import generate_paillier_keypair


@pytest.fixture(scope="session")
def keys():
    return generate_paillier_keypair(256)
