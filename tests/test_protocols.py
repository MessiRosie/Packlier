import numpy as np
import pytest

from packlier import EncryptedNumber, generate_paillier_keypair, toEncryptedNumber


@pytest.mark.parametrize("shape", [(), (4,), (2, 3), (2, 1, 3), (0,), (2, 0)])
def test_round_trip(keys, shape):
    public, private = keys
    plain = np.arange(np.prod(shape, dtype=int)).reshape(shape) if shape else np.array(3)
    encrypted = public.encrypt(plain)
    assert encrypted.shape == shape
    np.testing.assert_array_equal(private.decrypt(encrypted), plain)


@pytest.mark.parametrize("index", [0, (1, 2), (slice(None), slice(None, None, -1)), [2, 0], np.array([True, False, True]), (None, Ellipsis, 1), (slice(0, 0),)])
def test_getitem(keys, index):
    public, private = keys
    plain = np.arange(12).reshape(3, 4) / 7
    encrypted = public.encrypt(plain)
    selected = encrypted[index]
    assert isinstance(selected, EncryptedNumber)
    assert selected.public_key == public
    np.testing.assert_allclose(private.decrypt(selected), plain[index])
    np.testing.assert_array_equal(selected.exponent, encrypted.exponent[index])


def test_slice_is_independent(keys):
    public, private = keys
    encrypted = public.encrypt([1, 2, 3])
    original = encrypted.ciphertext().copy()
    selected = encrypted[:]
    selected.obfuscate()
    np.testing.assert_array_equal(encrypted.ciphertext(), original)
    np.testing.assert_array_equal(private.decrypt(selected), [1, 2, 3])


@pytest.mark.parametrize("left_shape,right_shape", [((2, 3), (3, 4)), ((3,), (3,)), ((3,), (3, 2)), ((2, 3), (3,)), ((2, 1, 3, 4), (5, 4, 2)), ((2, 0), (0, 3)), ((0,), (0,))])
@pytest.mark.parametrize("encrypted_left", [True, False])
def test_matmul(keys, left_shape, right_shape, encrypted_left):
    public, private = keys
    left = np.arange(np.prod(left_shape)).reshape(left_shape) / 4
    right = np.arange(np.prod(right_shape)).reshape(right_shape) / 2 - 3
    first, second = (public.encrypt(left), right) if encrypted_left else (left, public.encrypt(right))
    expected = left @ right
    for actual in (first @ second, np.matmul(first, second)):
        assert isinstance(actual, EncryptedNumber)
        assert actual.shape == expected.shape
        np.testing.assert_allclose(private.decrypt(actual), expected, atol=1e-12)


@pytest.mark.parametrize("operation", [np.add, np.subtract, np.multiply, np.true_divide])
@pytest.mark.parametrize("reverse", [False, True])
def test_binary_ufunc(keys, operation, reverse):
    public, private = keys
    plain = np.array([[1.5, -2, 3], [4, 5, 6]])
    other = np.array([2, -3, 4])
    encrypted = public.encrypt(plain)
    if reverse and operation is np.true_divide:
        with pytest.raises(TypeError):
            operation(other, encrypted)
    else:
        actual = operation(other, encrypted) if reverse else operation(encrypted, other)
        expected = operation(other, plain) if reverse else operation(plain, other)
        np.testing.assert_allclose(private.decrypt(actual), expected)


def test_operators_and_ufunc_unary(keys):
    public, private = keys
    encrypted = public.encrypt([2, -4])
    expressions = [(encrypted + 3, [5, -1]), (3 + encrypted, [5, -1]), (encrypted - 3, [-1, -7]), (3 - encrypted, [1, 7]), (encrypted * 2, [4, -8]), (2 * encrypted, [4, -8]), (encrypted / 2, [1, -2]), (-encrypted, [-2, 4]), (np.negative(encrypted), [-2, 4]), (np.positive(encrypted), [2, -4])]
    for actual, expected in expressions:
        np.testing.assert_allclose(private.decrypt(actual), expected)


@pytest.mark.parametrize("axis", [None, 0, 1, -1, (0, 1), ()])
@pytest.mark.parametrize("keepdims", [False, True])
def test_add_reduce(keys, axis, keepdims):
    public, private = keys
    plain = np.arange(6).reshape(2, 3) / 4
    actual = np.add.reduce(public.encrypt(plain), axis=axis, keepdims=keepdims, initial=2)
    expected = np.add.reduce(plain, axis=axis, keepdims=keepdims, initial=2)
    np.testing.assert_allclose(private.decrypt(actual), expected)


def test_reduce_mask_initial_and_empty(keys):
    public, private = keys
    encrypted = public.encrypt([[1, 2], [3, 4]])
    actual = np.add.reduce(encrypted, axis=None, where=[[True, False], [False, True]], initial=public.encrypt(7))
    assert private.decrypt(actual) == 12
    assert private.decrypt(np.add.reduce(public.encrypt([]))) == 0
    np.testing.assert_array_equal(private.decrypt(np.add.accumulate(encrypted, axis=1)), [[1, 3], [3, 7]])


@pytest.mark.parametrize("operation", [np.sin, np.exp, np.equal, np.maximum, np.multiply, np.matmul])
def test_unsupported_operations(keys, operation):
    public, _ = keys
    encrypted = public.encrypt([1, 2])
    with pytest.raises(TypeError):
        operation(encrypted) if operation.nin == 1 else operation(encrypted, encrypted)


def test_unsupported_ufunc_options(keys):
    public, _ = keys
    encrypted = public.encrypt([1, 2])
    with pytest.raises(TypeError):
        np.add(encrypted, 1, out=encrypted)
    with pytest.raises(TypeError):
        np.add(encrypted, 1, where=[True, False])
    with pytest.raises(TypeError):
        np.add.reduce(encrypted, dtype=np.float64)
    with pytest.raises(TypeError):
        np.multiply.reduce(encrypted)
    with pytest.raises(TypeError):
        np.add.at(encrypted, [0], 1)
    with pytest.raises(TypeError):
        np.asarray(encrypted)
    with pytest.raises(TypeError):
        bool(encrypted)


def test_mixed_keys_rejected(keys):
    public, private = keys
    other_public, _ = generate_paillier_keypair(256)
    first, second = public.encrypt([1]), other_public.encrypt([2])
    with pytest.raises(ValueError):
        first + second
    with pytest.raises(ValueError):
        private.decrypt(second)
    with pytest.raises(ValueError):
        np.add.reduce(first, initial=second[0])
    with pytest.raises(ValueError):
        toEncryptedNumber(np.array([first.toArray()[0], second.toArray()[0]], dtype=object))


def test_shapes_roundtrip_and_legacy(keys):
    public, private = keys
    encrypted = public.encrypt(np.arange(6).reshape(2, 3))
    assert len(encrypted) == 2
    assert encrypted.ndim == 2 and encrypted.size == 6
    np.testing.assert_array_equal(private.decrypt(encrypted.T), np.arange(6).reshape(2, 3).T)
    np.testing.assert_array_equal(private.decrypt(encrypted.reshape(3, 2)), np.arange(6).reshape(3, 2))
    np.testing.assert_array_equal(private.decrypt(toEncryptedNumber(encrypted.toArray())), np.arange(6).reshape(2, 3))
    restored = EncryptedNumber(public.n, encrypted.ciphertext(), encrypted.exponent)
    np.testing.assert_array_equal(private.decrypt(restored), np.arange(6).reshape(2, 3))
    assert toEncryptedNumber(np.empty((0, 2), dtype=object), public).shape == (0, 2)


def test_invalid_shapes_and_indexes(keys):
    public, _ = keys
    encrypted = public.encrypt([1, 2])
    with pytest.raises(ValueError):
        encrypted @ np.ones(3)
    with pytest.raises(ValueError):
        encrypted @ 2
    with pytest.raises(IndexError):
        encrypted[3]
    with pytest.raises(TypeError):
        encrypted[0] = 4


def test_protocols_do_not_decrypt(keys, monkeypatch):
    from phe.paillier import PaillierPrivateKey as BackendPrivateKey

    public, private = keys
    encrypted = public.encrypt([[1, 2], [3, 4]])

    def forbidden(*args, **kwargs):
        raise AssertionError("A public operation attempted decryption")

    with monkeypatch.context() as context:
        context.setattr(BackendPrivateKey, "decrypt", forbidden)
        context.setattr(BackendPrivateKey, "raw_decrypt", forbidden)
        results = [encrypted @ [2, 3], np.array([2, 3]) @ encrypted,
                   encrypted[:, 0], np.add(encrypted, 5),
                   np.add.reduce(encrypted, axis=0)]
    expected = [[8, 18], [11, 16], [1, 3], [[6, 7], [8, 9]], [4, 6]]
    for result, plain in zip(results, expected):
        np.testing.assert_array_equal(private.decrypt(result), plain)


def test_encrypted_broadcasting_and_scalar_index(keys):
    public, private = keys
    left = public.encrypt([[1.25], [2.5]])
    right = public.encrypt([1, -2, 3], precision=0.1)
    np.testing.assert_allclose(private.decrypt(left + right), [[2.25, -0.75, 4.25], [3.5, 0.5, 5.5]])
    scalar = public.encrypt(3)
    assert private.decrypt(scalar[()]) == 3
    assert private.decrypt(scalar[...]) == 3


def test_decrease_exponent_keeps_value(keys):
    public, private = keys
    encrypted = public.encrypt([1.5, -2.25])
    lowered = encrypted.decrease_exponent_to(encrypted.exponent - 1)
    np.testing.assert_array_equal(lowered.exponent, encrypted.exponent - 1)
    np.testing.assert_allclose(private.decrypt(lowered), [1.5, -2.25])
    with pytest.raises(ValueError):
        encrypted.decrease_exponent_to(encrypted.exponent + 1)
