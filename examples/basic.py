import numpy as np

from packlier import generate_paillier_keypair


def main():
    public, private = generate_paillier_keypair()
    plain = np.array([[1.25, -2.0], [3.0, 4.5]])
    encrypted = public.encrypt(plain)
    weights = np.array([[2.0], [3.0]])
    np.testing.assert_allclose(private.decrypt(encrypted @ weights), plain @ weights)
    np.testing.assert_allclose(private.decrypt(weights.T @ encrypted), weights.T @ plain)
    np.testing.assert_allclose(private.decrypt(encrypted[:, 0]), plain[:, 0])
    np.testing.assert_allclose(private.decrypt(np.add.reduce(encrypted, axis=0)), plain.sum(axis=0))
    print("Matrix multiplication, indexing, and NumPy reduction passed.")


if __name__ == "__main__":
    main()
