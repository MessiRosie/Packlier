import numpy as np
import pytest

from packlier import PaillierPrivateKey, generate_paillier_keypair
from packlier import paillier as implementation


def test_independent_randomizers(keys, monkeypatch):
    public, private = keys
    original = implementation._ScalarPublicKey.get_random_lt_n
    calls = []

    def counted(key):
        value = original(key)
        calls.append(value)
        return value

    monkeypatch.setattr(implementation._ScalarPublicKey, "get_random_lt_n", counted)
    encrypted = public.encrypt(np.ones((2, 3), dtype=int))
    assert len(calls) == 6
    assert len(set(encrypted.ciphertext().flat)) == 6
    encrypted.obfuscate()
    assert len(calls) == 12
    np.testing.assert_array_equal(private.decrypt(encrypted), np.ones((2, 3)))


def test_precision_and_negative_floats(keys):
    public, private = keys
    plain = np.array([1.23456789, -8.7654321])
    exact = public.encrypt(plain)
    coarse = public.encrypt(plain, precision=0.01)
    assert np.all(coarse.exponent > exact.exponent)
    np.testing.assert_allclose(private.decrypt(coarse), plain, atol=0.01)
    mixed = coarse + exact
    np.testing.assert_allclose(private.decrypt(mixed), plain * 2, atol=0.01)


@pytest.mark.parametrize("invalid", [complex(1, 2), np.nan, np.inf, "1", [object()]])
def test_plaintext_validation(keys, invalid):
    with pytest.raises(TypeError):
        keys[0].encrypt(invalid)


@pytest.mark.parametrize("precision", [0, -1, np.inf, np.nan, "0.1"])
def test_precision_validation(keys, precision):
    with pytest.raises(ValueError):
        keys[0].encrypt(1.2, precision=precision)


def test_range_and_division(keys):
    public, private = keys
    with pytest.raises(ValueError):
        public.encrypt(public.max_int + 1)
    with pytest.raises(OverflowError):
        private.decrypt(public.encrypt(public.max_int) + 1)
    with pytest.raises(ZeroDivisionError):
        public.encrypt(1) / 0


def test_from_totient_and_raw(keys):
    public, private = keys
    totient = (private._key.p - 1) * (private._key.q - 1)
    restored = PaillierPrivateKey.from_totient(public, totient)
    assert restored.decrypt(public.encrypt(-3.25)) == -3.25
    np.testing.assert_array_equal(private.raw_decrypt(public.raw_encrypt([1, 2, 3])), [1, 2, 3])
    with pytest.raises(ValueError):
        public.raw_encrypt([1, 2], r_value=1)
    with pytest.raises(ValueError):
        public.raw_encrypt(1, r_value=private._key.p)


@pytest.mark.parametrize("shape", [(), (5,), (3, 2), (0, 2)])
def test_parallel_round_trip(keys, shape):
    public, private = keys
    plain = np.arange(np.prod(shape)).reshape(shape) / 3 if shape else np.array(1.23456)
    encrypted = public.encrypt(plain, precision=0.001, is_pool=True, processes=2, partitions=3)
    actual = private.decrypt(encrypted, is_pool=True, processes=2, partitions=4)
    np.testing.assert_allclose(actual, plain, atol=0.001)
    np.testing.assert_allclose(private.decrypt(encrypted), actual)


def test_parallel_dot(keys):
    public, private = keys
    left = np.arange(15).reshape(5, 3) / 4
    right = np.arange(12).reshape(3, 4) - 2
    encrypted = public.encrypt(left)
    serial = encrypted.dot(right)
    parallel = encrypted.dot(right, is_pool=True, processes=2, partitions=3)
    assert type(serial) is type(parallel)
    np.testing.assert_allclose(private.decrypt(parallel), left.dot(right))
    np.testing.assert_allclose(private.decrypt(serial), private.decrypt(parallel))


def test_partition_argument_is_used(monkeypatch):
    seen = []

    class FakeExecutor:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def map(self, function, chunks):
            seen.extend(len(chunk) for chunk in chunks)
            return map(function, chunks)

    monkeypatch.setattr(implementation, "ProcessPoolExecutor", FakeExecutor)
    assert implementation._parallel(list, list(range(10)), processes=2, partitions=3) == list(range(10))
    assert seen == [3, 3, 4]


@pytest.mark.parametrize("kwargs", [{"processes": 0}, {"partitions": 0}, {"partitions": 1.5}, {"processes": True}])
def test_parallel_argument_validation(keys, kwargs):
    with pytest.raises(ValueError):
        keys[0].encrypt([1, 2], is_pool=True, **kwargs)


@pytest.mark.parametrize("bits", [0, 31, 33, True, 64.5])
def test_key_length_validation(bits):
    with pytest.raises(ValueError):
        generate_paillier_keypair(bits)


def test_input_not_mutated_and_large_integer_preserved(keys):
    public, private = keys
    plain = np.array([np.int64(7), 1.5], dtype=object)
    public.encrypt(plain)
    assert isinstance(plain[0], np.int64)
    mixed = np.array([2**60 + 1, 1.5], dtype=object)
    recovered = private.decrypt(public.encrypt(mixed))
    assert recovered[0] == 2**60 + 1


def test_randomizer_rejects_non_coprime_value(keys, monkeypatch):
    from phe.paillier import PaillierPublicKey as BackendPublicKey

    public, private = keys
    candidates = iter([private._key.p, 2])
    monkeypatch.setattr(BackendPublicKey, "get_random_lt_n", lambda key: next(candidates))
    assert public._key.get_random_lt_n() == 2


@pytest.mark.parametrize("invalid", [0, -1, 1.5])
def test_raw_decrypt_validation(keys, invalid):
    with pytest.raises(ValueError):
        keys[1].raw_decrypt(invalid)
