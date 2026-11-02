# Provenance and licensing

Packlier's NumPy adapter is newly written, inspired by the API and
limitations of the PyPI `paillier-numpy` 0.0.2 distribution (project metadata
names Galloroc / Galloroc1). That distribution refers to `data61/python-paillier`
as its main reference project.

No source files from `paillier-numpy` are bundled here. Its inspected source
archive has an empty LICENSE file, an MIT classifier, and a utility module
with a GPL notice. This package does not assume that metadata grants an
unambiguous MIT license to all of those files.

The scalar cryptographic implementation is the separately installed `phe`
dependency (python-paillier 1.5.x), whose package metadata identifies GPLv3.
Its own authorship and license notices remain in that dependency. NumPy is
also installed separately and retains its own license and notices.

This new package is distributed under GPL-3.0-or-later. The included LICENSE
contains the GNU GPL version 3 text, obtained from the installed `phe` 1.5.0
distribution. Neither original project has endorsed this package.
