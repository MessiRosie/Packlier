# Security boundaries

## Import-time automatic installation

Since 0.1.1, first import in a managed installation can contact GitHub and
install a newer same-major/minor stable patch without another confirmation.
Set `PACKLIER_AUTO_UPDATE=off` before any import to disable this side effect.
Use the opt-out for production, air-gapped, and reproducible/pinned environments.

The source is fixed to public releases of `MessiRosie/Packlier`. Only a
universal wheel with matching name/version, compatible installed dependencies,
and a matching GitHub asset SHA-256/size is accepted. HTTPS redirects are
restricted to GitHub's listed download hosts. The digest is not a maintainer
signature: compromise of that repository or release publishing permissions
can compromise auto-updating clients. Protect those permissions accordingly.

Installation runs as the importing user through the current interpreter's pip;
it never escalates privileges and does not upgrade dependencies. It is not a
transactional package manager. Failure after starting installation stops the
import and leaves a persistent failure record requiring manual repair. Success
also stops the import and requires restarting the process. No automatic
rollback, hot reload, or unattended process restart is promised.

The file lock serializes participating imports/updates but cannot prevent
external pip commands or already-running processes from using the same files.
Quiesce workers before updating shared environments. The opt-out bypasses the
updater entirely, including its failure record; do not use it to run code from
an unverified failed installation.

## Cryptography

- This package has not received an independent cryptographic audit. Passing
  tests is not a security certification. Do not treat it as a production
  security boundary without a separate review and threat model.
- Default key generation uses 3072 bits. Smaller sizes are accepted for
  testing and interoperability; their acceptance is not a safety endorsement.
- Each plaintext element and each explicit re-randomization obtains a fresh
  randomizer coprime to the public modulus. Randomizers are not shared across
  an array. This intentionally avoids the original array-wide reuse.
- `ciphertext()` defaults to the backend's secure export path, which
  randomizes arithmetic results before export. Do not expose
  `ciphertext(be_secure=False)` from derived results. `toArray()` exposes
  scalar encrypted objects, not a serialized or authenticated message.
- Paillier is malleable by design. This wrapper does not authenticate
  ciphertexts, senders, public keys, or messages. It supplies no signatures,
  transport security, ciphertext integrity protocol, or zero-knowledge proof.
- Shapes, public keys, encoding exponents, public indices/masks, plaintext
  operands, and control flow are not hidden. Indexing is not oblivious access.
- Homomorphic addition and multiplication by public values are supported.
  Encrypted-encrypted multiplication, comparisons, nonlinear functions, and
  division by encrypted data are not supplied.
- Private-key operations and Python/NumPy object arithmetic are not promised
  to be constant-time. This is not a hardened side-channel-resistant backend.
- Multiprocess decryption sends the private key to local worker processes.
  It must run only on a trusted machine and under a trusted account.
- Fixed-point overflow and rounding remain possible. Input-range checks and
  the backend's overflow checks do not prove arbitrary computations safe.
  Bound your inputs, intermediate magnitudes, and precision separately.
- Never load untrusted pickle data. No network server, remote execution
  protocol, or private-key persistence is included.

If reporting a vulnerability, do not publish private keys, sensitive
plaintexts, or production ciphertexts. Contact the repository owner privately
before publishing exploit details.
