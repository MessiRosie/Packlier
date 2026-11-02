"""Packlier's NumPy protocol layer over python-paillier's scalar cryptography."""

from concurrent.futures import ProcessPoolExecutor
import copy
import math
import multiprocessing
import numbers
import os

import numpy as np
from phe import paillier as backend


def _plain_array(value):
    array = np.array(value, dtype=object, copy=True)
    for index in np.ndindex(array.shape):
        item = array[index]
        if isinstance(item, np.generic):
            item = item.item()
        if isinstance(item, numbers.Integral):
            array[index] = int(item)
        elif isinstance(item, numbers.Real) and math.isfinite(item):
            array[index] = float(item)
        else:
            raise TypeError("Plaintext must contain finite real numbers")
    return array


def _positive_count(value, name):
    if isinstance(value, bool) or not isinstance(value, numbers.Integral) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return int(value)


def _parallel(function, values, processes, partitions):
    workers = max(1, (os.cpu_count() or 1) - 1) if processes is None else _positive_count(processes, "processes")
    blocks = workers * 4 if partitions is None else _positive_count(partitions, "partitions")
    if not values:
        return []
    blocks = min(blocks, len(values))
    chunks = [values[start * len(values) // blocks:(start + 1) * len(values) // blocks] for start in range(blocks)]
    with ProcessPoolExecutor(max_workers=min(workers, blocks), mp_context=multiprocessing.get_context("spawn")) as executor:
        return [item for chunk in executor.map(function, chunks) for item in chunk]


def _encrypt_chunk(tasks):
    return [key.encrypt(value, precision=precision) for key, value, precision in tasks]


def _decrypt_chunk(tasks):
    return [key.decrypt(value) for key, value in tasks]


def _dot_chunk(tasks):
    return [np.dot(left, right) for left, right in tasks]


class _ScalarPublicKey(backend.PaillierPublicKey):
    def get_random_lt_n(self):
        while True:
            candidate = super().get_random_lt_n()
            if math.gcd(candidate, self.n) == 1:
                return candidate


class PaillierPublicKey:
    """Public key supporting scalar and array encryption with fresh randomness."""

    def __init__(self, n):
        if not isinstance(n, numbers.Integral) or isinstance(n, bool) or n < 3:
            raise ValueError("n must be an integer greater than two")
        self._key = _ScalarPublicKey(int(n))

    @property
    def n(self):
        return self._key.n

    @property
    def nsquare(self):
        return self._key.nsquare

    @property
    def g(self):
        return self._key.g

    @property
    def max_int(self):
        return self._key.max_int

    def __eq__(self, other):
        return isinstance(other, PaillierPublicKey) and self.n == other.n

    def __hash__(self):
        return hash(self.n)

    def encrypt(self, value, precision=None, is_pool=False, processes=None, partitions=None):
        """Encrypt finite real values, independently randomizing every element."""
        if precision is not None and (not isinstance(precision, numbers.Real) or not math.isfinite(precision) or precision <= 0):
            raise ValueError("precision must be a finite positive number")
        plain = _plain_array(value)
        tasks = [(self._key, item, precision) for item in plain.flat]
        encrypted = _parallel(_encrypt_chunk, tasks, processes, partitions) if is_pool else _encrypt_chunk(tasks)
        return EncryptedNumber._from_values(self, np.asarray(encrypted, dtype=object).reshape(plain.shape))

    def encrypt_(self, value, precision=None):
        return self.encrypt(value, precision=precision)

    def raw_encrypt(self, plaintext, r_value=None):
        """Encrypt unencoded integers; an explicit randomizer is scalar-only."""
        plain = _plain_array(plaintext)
        if r_value is not None and plain.ndim != 0:
            raise ValueError("An explicit randomizer cannot be shared across an array")
        if r_value is not None and (not isinstance(r_value, numbers.Integral) or not 0 < r_value < self.n or math.gcd(int(r_value), self.n) != 1):
            raise ValueError("r_value must be an invertible integer modulo n")
        result = np.empty(plain.shape, dtype=object)
        for index in np.ndindex(plain.shape):
            item = plain[index]
            if not isinstance(item, int) or not 0 <= item < self.n:
                raise ValueError("Raw plaintext must be an integer in [0, n)")
            result[index] = self._key.raw_encrypt(item, r_value=r_value)
        return result.item() if result.ndim == 0 else result


class PaillierPrivateKey:
    """Private key using the backend's CRT decryption."""

    def __init__(self, n, p, q):
        self.public_key = n if isinstance(n, PaillierPublicKey) else PaillierPublicKey(n)
        self._key = backend.PaillierPrivateKey(self.public_key._key, int(p), int(q))

    @property
    def n(self):
        return self.public_key.n

    @classmethod
    def from_totient(cls, public_key, totient):
        key = backend.PaillierPrivateKey.from_totient(public_key._key, totient)
        return cls(public_key, key.p, key.q)

    def decrypt(self, value, is_pool=False, processes=None, partitions=None):
        """Decrypt an encrypted array, scalar, or legacy object array."""
        if isinstance(value, EncryptedNumber):
            if value.public_key != self.public_key:
                raise ValueError("Ciphertext belongs to a different public key")
            array = value._values
        else:
            array = np.asarray(value, dtype=object)
        for item in array.flat:
            if not isinstance(item, backend.EncryptedNumber):
                raise TypeError("Expected encrypted numbers")
            if item.public_key.n != self.n:
                raise ValueError("Ciphertext belongs to a different public key")
        tasks = [(self._key, item) for item in array.flat]
        values = _parallel(_decrypt_chunk, tasks, processes, partitions) if is_pool else _decrypt_chunk(tasks)
        if array.ndim == 0:
            return values[0]
        preserve_integers = any(isinstance(item, float) for item in values) and any(isinstance(item, int) and abs(item) > 2**53 for item in values)
        return np.asarray(values, dtype=object if preserve_integers else None).reshape(array.shape)

    def decrypt_(self, value):
        return self.decrypt(value)

    def raw_decrypt(self, ciphertext):
        array = np.asarray(ciphertext, dtype=object)
        result = np.empty(array.shape, dtype=object)
        for index in np.ndindex(array.shape):
            cipher = array[index]
            if not isinstance(cipher, numbers.Integral) or not 0 < cipher < self.public_key.nsquare or math.gcd(int(cipher), self.n) != 1:
                raise ValueError("Ciphertext must be invertible modulo n squared")
            result[index] = self._key.raw_decrypt(int(cipher))
        return result.item() if result.ndim == 0 else result


class EncryptedNumber:
    """An encrypted scalar or array with a single public key.

    Indexing returns an encrypted copy. Supported ufuncs never decrypt data.
    Output buffers, masked writes, and implicit ndarray conversion are refused.
    """

    __array_priority__ = 1000

    def __init__(self, n, ciphertext, exponent):
        self.public_key = n if isinstance(n, PaillierPublicKey) else PaillierPublicKey(n)
        ciphertexts, exponents = np.broadcast_arrays(np.asarray(ciphertext, dtype=object), np.asarray(exponent, dtype=object))
        self._values = np.empty(ciphertexts.shape, dtype=object)
        for index in np.ndindex(ciphertexts.shape):
            cipher, power = ciphertexts[index], exponents[index]
            if not isinstance(cipher, numbers.Integral) or not 0 < cipher < self.public_key.nsquare or math.gcd(int(cipher), self.n) != 1:
                raise ValueError("Ciphertext must be invertible modulo n squared")
            if not isinstance(power, numbers.Integral):
                raise TypeError("Exponent must be an integer")
            self._values[index] = backend.EncryptedNumber(self.public_key._key, int(cipher), int(power))

    @classmethod
    def _from_values(cls, public_key, values):
        result = cls.__new__(cls)
        result.public_key = public_key
        source = np.asarray(values, dtype=object)
        result._values = np.empty(source.shape, dtype=object)
        for index in np.ndindex(source.shape):
            item = source[index]
            if isinstance(item, backend.EncryptedNumber):
                if item.public_key.n != public_key.n:
                    raise ValueError("Cannot combine different public keys")
                result._values[index] = copy.copy(item)
            else:
                result._values[index] = public_key._key.encrypt(_plain_array(item).item())
        return result

    @property
    def n(self):
        return self.public_key.n

    @property
    def nsquare(self):
        return self.public_key.nsquare

    @property
    def max_int(self):
        return self.public_key.max_int

    @property
    def shape(self):
        return self._values.shape

    @property
    def ndim(self):
        return self._values.ndim

    @property
    def size(self):
        return self._values.size

    @property
    def exponent(self):
        result = np.empty(self.shape, dtype=object)
        for index in np.ndindex(self.shape):
            result[index] = self._values[index].exponent
        return result.item() if self.ndim == 0 else result

    @property
    def T(self):
        return self.transpose()

    def __repr__(self):
        return f"EncryptedNumber(shape={self.shape}, key_bits={self.n.bit_length()})"

    def __len__(self):
        return len(self._values)

    def __bool__(self):
        raise TypeError("The truth value of encrypted data is unavailable")

    def __array__(self, dtype=None, copy=None):
        raise TypeError("Implicit ndarray conversion is disabled; use toArray() explicitly")

    def __getitem__(self, key):
        """Index ciphertexts and their encoding metadata together, without decryption."""
        return self._from_values(self.public_key, self._values[key])

    def copy(self):
        return self._from_values(self.public_key, self._values)

    def reshape(self, *shape):
        return self._from_values(self.public_key, self._values.reshape(*shape))

    def transpose(self, *axes):
        return self._from_values(self.public_key, self._values.transpose(*axes))

    def toArray(self):
        """Return a copy containing python-paillier scalar encrypted objects."""
        return self.copy()._values

    def ciphertext(self, be_secure=True):
        result = np.empty(self.shape, dtype=object)
        for index in np.ndindex(self.shape):
            result[index] = self._values[index].ciphertext(be_secure=be_secure)
        return result.item() if self.ndim == 0 else result

    def obfuscate(self):
        """Re-randomize every scalar independently, in place."""
        for item in self._values.flat:
            item.obfuscate()

    def decrease_exponent_to(self, new_exp):
        exponents = np.broadcast_to(np.asarray(new_exp, dtype=object), self.shape)
        values = np.empty(self.shape, dtype=object)
        for index in np.ndindex(self.shape):
            if not isinstance(exponents[index], numbers.Integral):
                raise TypeError("Exponent must be an integer")
            values[index] = self._values[index].decrease_exponent_to(int(exponents[index]))
        return self._from_values(self.public_key, values)

    def _operand(self, other):
        if isinstance(other, EncryptedNumber):
            if self.public_key != other.public_key:
                raise ValueError("Cannot combine different public keys")
            return other._values
        return _plain_array(other)

    def _binary(self, other, operation, reverse=False):
        if operation in (np.multiply, np.true_divide) and isinstance(other, EncryptedNumber):
            raise TypeError("Ciphertext-ciphertext multiplication/division is unsupported")
        if operation is np.true_divide and reverse:
            raise TypeError("Division by encrypted data is unsupported")
        left, right = self._values, self._operand(other)
        if reverse:
            left, right = right, left
        return self._from_values(self.public_key, operation(left, right))

    def __add__(self, other):
        return self._binary(other, np.add)

    def __radd__(self, other):
        return self._binary(other, np.add, reverse=True)

    def __sub__(self, other):
        return self._binary(other, np.subtract)

    def __rsub__(self, other):
        return self._binary(other, np.subtract, reverse=True)

    def __mul__(self, other):
        return self._binary(other, np.multiply)

    def __rmul__(self, other):
        return self._binary(other, np.multiply, reverse=True)

    def __truediv__(self, other):
        return self._binary(other, np.true_divide)

    def __neg__(self):
        return self * -1

    def __pos__(self):
        return self.copy()

    def _matmul(self, other, reverse=False):
        if isinstance(other, EncryptedNumber):
            raise TypeError("Matrix multiplication requires one plaintext operand")
        left, right = self._values, self._operand(other)
        if reverse:
            left, right = right, left
        return self._from_values(self.public_key, np.matmul(left, right))

    def __matmul__(self, other):
        """Encrypted @ plaintext, including vector and batch broadcasting."""
        return self._matmul(other)

    def __rmatmul__(self, other):
        """Plaintext @ encrypted, without decrypting the encrypted operand."""
        return self._matmul(other, reverse=True)

    def dot(self, other, is_pool=False, processes=None, partitions=None):
        """NumPy dot semantics; parallel and serial paths return the same type."""
        if isinstance(other, EncryptedNumber):
            raise TypeError("Dot requires a plaintext right operand")
        right = self._operand(other)
        if is_pool and self.ndim > 1 and self.shape[0]:
            tasks = [(self._values[index:index + 1], right) for index in range(self.shape[0])]
            values = np.concatenate(_parallel(_dot_chunk, tasks, processes, partitions), axis=0)
        else:
            if is_pool:
                if processes is not None:
                    _positive_count(processes, "processes")
                if partitions is not None:
                    _positive_count(partitions, "partitions")
            values = np.dot(self._values, right)
        return self._from_values(self.public_key, values)

    def __array_ufunc__(self, ufunc, method, *inputs, **kwargs):
        """Dispatch supported arithmetic and additive reductions only."""
        output = kwargs.pop("out", None)
        if output is not None and any(item is not None for item in output):
            return NotImplemented
        if method == "__call__":
            if kwargs:
                return NotImplemented
            if ufunc in (np.negative, np.positive) and len(inputs) == 1:
                return -self if ufunc is np.negative else +self
            if len(inputs) != 2:
                return NotImplemented
            left, right = inputs
            if ufunc is np.matmul:
                return left._matmul(right) if isinstance(left, EncryptedNumber) else right._matmul(left, reverse=True)
            if ufunc not in (np.add, np.subtract, np.multiply, np.true_divide):
                return NotImplemented
            if isinstance(left, EncryptedNumber):
                return left._binary(right, ufunc)
            return right._binary(left, ufunc, reverse=True)
        if ufunc is np.add and method in ("reduce", "accumulate") and len(inputs) == 1:
            allowed = {"axis", "dtype"} | ({"keepdims", "initial", "where"} if method == "reduce" else set())
            if set(kwargs) - allowed:
                return NotImplemented
            dtype = kwargs.get("dtype")
            if dtype is not None and np.dtype(dtype) != np.dtype(object):
                return NotImplemented
            kwargs["dtype"] = object
            if "initial" in kwargs:
                initial = kwargs["initial"]
                if initial is not None:
                    initial_array = self._operand(initial)
                    if initial_array.ndim:
                        raise ValueError("initial must be a scalar")
                    kwargs["initial"] = initial_array.item()
            values = getattr(np.add, method)(self._values, **kwargs)
            return self._from_values(self.public_key, values)
        return NotImplemented


def generate_paillier_keypair(n_length=3072):
    """Generate a public/private pair; tiny keys are suitable only for tests."""
    if isinstance(n_length, bool) or not isinstance(n_length, numbers.Integral) or n_length < 32 or n_length % 2:
        raise ValueError("n_length must be an even integer of at least 32 bits")
    public, private = backend.generate_paillier_keypair(n_length=int(n_length))
    return PaillierPublicKey(public.n), PaillierPrivateKey(public.n, private.p, private.q)


def toEncryptedNumber(array, public_key=None):
    """Wrap an object array; empty arrays require an explicit public key."""
    values = np.asarray(array, dtype=object)
    if public_key is None:
        if not values.size:
            raise ValueError("An empty array needs public_key")
        first = values.flat[0]
        if not isinstance(first, backend.EncryptedNumber):
            raise TypeError("Expected scalar python-paillier encrypted numbers")
        public_key = PaillierPublicKey(first.public_key.n)
    for item in values.flat:
        if not isinstance(item, backend.EncryptedNumber):
            raise TypeError("Expected scalar python-paillier encrypted numbers")
    return EncryptedNumber._from_values(public_key, values)
