# Packlier

A new, installable encrypted-array package inspired by `paillier-numpy 0.0.2`.
It implements `@`, indexing, and selected NumPy ufuncs without decrypting data.

**Implementation boundary:** this is a reimplementation of the NumPy layer,
not a verbatim fork of the original package. Scalar encryption, encoding, and
CRT decryption use `python-paillier` (`phe`), the project also referenced by
the original package. Each array element receives independent randomness.

This is research software, not independently audited cryptographic software.
See [SECURITY.md](SECURITY.md) before using sensitive data.

## Install

Requires Python 3.10+ and NumPy 1.26 or 2.x. From this repository:

```bash
python -m pip install .
# Optional GMP acceleration:
python -m pip install '.[fast]'
# Development and tests:
python -m pip install -e '.[test]'
python -m pytest
python -m build
```

The distribution name is `Packlier`; the import name is
`packlier`. This repository is not a claim of publication on PyPI.

## Quick start

```python
import numpy as np
from packlier import generate_paillier_keypair

public, private = generate_paillier_keypair()  # 3072-bit default
matrix = np.array([[1.25, -2.0], [3.0, 4.5]])
encrypted = public.encrypt(matrix)

product = encrypted @ np.array([[2], [3]])
np.testing.assert_allclose(private.decrypt(product), matrix @ [[2], [3]])

left_product = np.array([[2, 3]]) @ encrypted
selected = encrypted[:, 0]
shifted = np.add(encrypted, 2)
scaled = np.multiply(encrypted, np.array([2, -1]))
column_sums = np.add.reduce(encrypted, axis=0)
np.testing.assert_allclose(private.decrypt(column_sums), matrix.sum(axis=0))
```

## The three new interfaces

### Matrix multiplication: `__matmul__` and `__rmatmul__`

Both `encrypted @ plaintext` and `plaintext @ encrypted` return an
`EncryptedNumber`. `np.matmul` also dispatches to the same implementation.
Exactly one operand must be encrypted. Shapes follow NumPy `matmul` semantics:
vector inner products, matrix-vector products, matrix products, and broadcast
batch dimensions. Scalars and incompatible dimensions raise `ValueError`.
Zero-length contractions produce encrypted zeros.

`encrypted.dot(plaintext)` retains NumPy `dot` semantics, which differ from
`matmul` for higher-dimensional inputs. Neither operation supports two
encrypted operands.

### Indexing: `__getitem__`

```python
element = encrypted[0, 1]      # encrypted scalar, shape ()
row = encrypted[0]            # encrypted vector
block = encrypted[:2, ::-1]   # slice
rows = encrypted[[1, 0]]      # advanced indexing
masked = encrypted[np.array([True, False])]
```

Integer indices, slices, tuples, ellipses, `None`, integer arrays, and boolean
masks follow NumPy indexing. The result retains the key, ciphertext, and
per-element exponent. Results are copies, not writable views; re-randomizing
a selection does not modify its parent. Assignment through `[]` is not
implemented. An index or mask must be plaintext.

### NumPy dispatch: `__array_ufunc__`

| Operation | Supported inputs / methods |
| --- | --- |
| `np.add`, `np.subtract` | Encrypted/plaintext in either order, or same-key encrypted/encrypted; broadcasting |
| `np.multiply` | Exactly one encrypted operand; broadcasting |
| `np.true_divide` | Encrypted numerator and nonzero plaintext denominator |
| `np.negative`, `np.positive` | Encrypted input |
| `np.matmul` | Exactly one encrypted operand |
| `np.add.reduce` | `axis`, `keepdims`, plaintext boolean `where`, scalar plaintext/encrypted `initial`, `dtype=object` |
| `np.add.accumulate` | `axis`, `dtype=object` |

Reductions always return an encrypted object, including scalar and empty-sum
results. A scalar `initial` must use the same key if encrypted. Reduction
defaults, including `axis=0`, match the corresponding NumPy ufunc.

Unsupported ufuncs/methods return `NotImplemented` from the protocol, allowing
NumPy to raise `TypeError`. Concrete unsupported encryption operations also
raise `TypeError`. Non-`None` output buffers, `at`, general `dtype` casts, and
masked elementwise writes are deliberately unsupported; this avoids partial
mutation and plaintext coercion. `where` is supported only for additive
reduction. Other elementwise keywords (even default-valued ones) are rejected.

`__array_function__` is not implemented. Use `np.add.reduce(encrypted)` rather
than assuming arbitrary functions such as `np.sum`, `np.concatenate`, or
`np.linalg` work. Implicit `np.asarray(encrypted)` is rejected. Explicit
`encrypted.toArray()` returns copies of **scalar `phe.EncryptedNumber`
objects**, not plaintext. These scalars expose the backend's API rather than
this array wrapper's API.

## Public API

```python
generate_paillier_keypair(n_length=3072)
PaillierPublicKey(n)
PaillierPrivateKey(n_or_public_key, p, q)
PaillierPrivateKey.from_totient(public_key, totient)

public.encrypt(value, precision=None, is_pool=False, processes=None, partitions=None)
private.decrypt(value, is_pool=False, processes=None, partitions=None)

EncryptedNumber(n_or_public_key, ciphertext, exponent)
toEncryptedNumber(object_array, public_key=None)

encrypted.dot(plaintext, is_pool=False, processes=None, partitions=None)
encrypted.ciphertext(be_secure=True)
encrypted.obfuscate()
encrypted.decrease_exponent_to(new_exp)
encrypted.toArray()
encrypted.copy()
encrypted.reshape(*shape)
encrypted.transpose(*axes)
```

Additional properties: `shape`, `ndim`, `size`, `T`, `exponent`, `public_key`,
`n`, `nsquare`, and `max_int`. Scalar decryptions return Python numbers;
array decryptions return ndarrays. Mixed huge integers/floats retain object
dtype to avoid silently rounding the integers.

`precision` is forwarded to the scalar encoder. Values must be finite real
numbers within the backend's encoding range. Integer, floating, scalar,
empty, and higher-dimensional arrays are supported. Complex numbers and
nonfinite values are rejected. Precision applies to encoding; it is not a
bound on the total error of subsequent calculations.

`encrypt_` and `decrypt_` are serial aliases. The low-level `raw_encrypt` and
`raw_decrypt` operate on unencoded residues. Explicit `r_value` is accepted
only for scalar raw encryption; reusing it is unsafe. Most callers should
use the high-level API instead.

## Multiprocessing

```python
import numpy as np
from packlier import generate_paillier_keypair

def main():
    public, private = generate_paillier_keypair()
    encrypted = public.encrypt(np.arange(12).reshape(4, 3), is_pool=True,
                               processes=2, partitions=3)
    result = encrypted.dot(np.ones((3, 2), dtype=int), is_pool=True,
                           processes=2, partitions=3)
    print(private.decrypt(result, is_pool=True, processes=2, partitions=3))

if __name__ == "__main__":
    main()
```

Run multiprocessing from an importable script guarded by `__main__`.
The implementation uses the `spawn` context. Encryption/decryption partition
flattened elements and restore the original shape. Parallel dot partitions
rows; scalar/vector or empty-leading-axis dot inputs use the serial path.
Both paths return the same wrapper type. `processes` and `partitions` must
be positive integers when pooling is requested. There is no GPU or
distributed execution backend, and no performance parity claim with the
original package. Multiprocessing overhead can outweigh benefits for small
inputs.

## Migration from paillier-numpy 0.0.2

- Replace `from paillier import ...` with `from packlier import ...`.
- Common encryption, decryption, arithmetic, `.dot()`, and `.toArray()`
  workflows remain available. This is not a full drop-in replacement for
  every internal helper or serialized object of the original package.
- `precision` and encryption/decryption `partitions` now take effect.
- Parallel dot returns `EncryptedNumber`, like serial dot.
- Each encrypted element receives its own randomizer. The old array-wide
  randomizer reuse is not reproduced.
- Ciphertexts and keys are not automatically saved to disk. Legacy pickle
  compatibility, keyrings, and custom serialization formats are not provided.

## Development

Tests cover operators, both matmul directions, batched and empty matmul,
indexing, mixed encoding exponents, arithmetic broadcasting, reductions,
unsupported operations, key isolation, randomizer allocation, parameter
validation, and actual spawn-based multiprocessing. CI builds a wheel and
runs the suite using its installed contents.

Tests use deliberately tiny keys for speed. Never copy their key size into
a production application. See [NOTICE.md](NOTICE.md) for provenance and
[LICENSE](LICENSE) for the GPL-3.0-or-later license.
