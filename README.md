# Packlier

A new, installable encrypted-array package inspired by `paillier-numpy 0.0.2`.
It implements `@`, indexing, and selected NumPy ufuncs without decrypting data.

**Implementation boundary:** this is a reimplementation of the NumPy layer,
not a verbatim fork of the original package. Scalar encryption, encoding, and
CRT decryption use `python-paillier` (`phe`), the project also referenced by
the original package. Each array element receives independent randomness.

This is research software, not independently audited cryptographic software.
See [SECURITY.md](SECURITY.md) before using sensitive data.

**Import-time side effect (0.1.1+):** in a normal writable installation,
the first import in each process contacts the fixed GitHub Releases source
and automatically installs an eligible patch update if available. It then
stops the import and requires a restart. Set `PACKLIER_AUTO_UPDATE=off`
**before importing** to disable this behavior. See [Automatic updates](#automatic-updates).

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

## Automatic updates

No extra application call is required:

```python
from packlier import generate_paillier_keypair
```

Before loading the cryptographic API, Packlier 0.1.1+ checks the public releases
of **`MessiRosie/Packlier` on GitHub**, not a same-named PyPI project. The update
source is fixed in code; environment variables cannot redirect it to a
different repository or package index. Installing the updater-capable version
once is necessary: older Packlier installations cannot discover this feature
by themselves.

### Import behavior

1. Obtain an installation-wide file lock and check for unfinished updates.
2. Query up to the latest 100 GitHub releases. Select the newest non-draft,
   non-prerelease patch in the **same major/minor series**. For example,
   `0.1.1 -> 0.1.2` is eligible; `0.1.1 -> 0.2.0` is not. This is a selection
   policy, not proof that upstream changes are backward compatible.
3. Download only the matching universal `packlier-VERSION-py3-none-any.whl`
   from this repository. Require the GitHub asset's SHA-256 digest and byte
   count, verify both, and inspect wheel metadata, Python compatibility, and
   required installed dependency versions before running pip.
4. Invoke the current interpreter's pip in a separate subprocess with
   `--no-index --no-deps`. Dependency upgrades, source distributions, unknown
   download hosts, and arbitrary update commands are not permitted.
5. If installation succeeds, raise `PacklierUpdatedRestartRequired`
   (an `ImportError`) **before importing the cryptographic API**. Rerun the
   script, restart the notebook kernel, or restart the service. Retrying an
   import in the same process is refused. Packlier never restarts your program
   itself and does not hot-reload code.

If there is no eligible release, the import proceeds normally. If the check
or download fails (offline, API rate limit, hash mismatch,
or incompatible dependency requirements), the import proceeds with the current
version and emits `PacklierUpdateWarning`. Installation has not begun in those
cases. Releases without the required wheel/digest are ignored. Network timeouts
are bounded per request (2 seconds for release metadata,
30 seconds for downloading); an unavailable network can still add import latency.

Once pip has been started, a failure or interruption is **fatal to the import**.
There is no claim of atomic installation or automatic rollback. A durable
`.packlier-update-state.json` beside the installed package records the attempt;
later imports refuse to trust an unfinished installation. Repair/reinstall it
manually from a trusted wheel with auto-update disabled, verify the environment,
then remove the state file named in the error before enabling updates again.

Concurrent imports in the same installation serialize using
`.packlier-update.lock`, outside the directory replaced by pip. A waiting import
rechecks the installed version; if its loaded initializer is stale, it also
requires a restart. Lock acquisition times out after 15 seconds instead of
silently importing during another update. Installer execution has a 180-second
timeout. The lock is an import/update lock, **not a lifetime lock on every
process already using Packlier**: stop existing workers before allowing an
update to a shared environment. Prefer disabled auto-update plus controlled
deployment in production services.

### Disable updates / reproducible environments

```bash
PACKLIER_AUTO_UPDATE=off python your_program.py
```

Or, before the first Packlier import (including indirect imports):

```python
import os
os.environ["PACKLIER_AUTO_UPDATE"] = "off"
from packlier import generate_paillier_keypair
```

Accepted disable values are `off`, `0`, `false`, and `no`, case-insensitively.
With this switch, the updater performs no checking, locking, or installation.
This also bypasses its failure-state guard; only do that for recovery after
verifying the environment, not to ignore a failed install. CI/tests disable
auto-update explicitly. Use it for pinned deployments as well: an importer
cannot infer the constraints from an earlier requirements/lock file.

Source checkouts, editable installs, nonstandard/user-site installs, and
externally managed system Python are not automatically modified. A normal
virtual environment is the recommended installation location. Permission
failure acquiring the lock skips automatic updating with a warning. The
updater needs pip in that interpreter; a missing pip is treated as a failed
installation attempt and reported, not silently ignored. Private release
sources and authenticated GitHub downloads are not supported by this version.

### Publishing discoverable updates

Pushing ordinary commits does **not** trigger an installed user's upgrade.
A release needs a stable `vMAJOR.MINOR.PATCH` tag and the matching wheel asset.
The included `.github/workflows/release.yml` builds and tests the tagged
version, then uploads the wheel and source archive to a GitHub Release.
GitHub supplies the asset digest read by the updater. The release workflow
needs Actions enabled and its declared `contents: write` permission.

For a future patch release, update both `pyproject.toml` and `__version__` in
`src/packlier/__init__.py`, commit, then intentionally create and push its tag:

```bash
git tag v0.1.2
git push origin v0.1.2
```

Do not run that example until the code actually has version `0.1.2`. This
workflow publishes to GitHub Releases, not PyPI. SHA-256 verifies that the
download matches GitHub's asset metadata; it is **not** an independent
signature or protection against a compromised repository maintainer.

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
