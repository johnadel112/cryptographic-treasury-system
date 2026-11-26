"""Automated tests for Divan's Milestone 2 implementation.

Covers:
  - treasury/sharing.py  (Shamir SSS, Feldman VSS, Lagrange coefficients)
  - treasury/opening.py  (Chaum-Pedersen proofs, combination)
  - treasury/vault.py    (ElGamal, HKDF, AES-GCM, vault setup/open)
  - Attack A5            (weak no-proof mode vs secure mode)

Compatible with:  python -m unittest discover -s tests -v
"""
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project root is on the path when run directly
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from treasury.config import G, P, Q
from treasury.opening import (
    combine_decryption_shares,
    make_decryption_share,
    verify_decryption_share,
)
from treasury.sharing import (
    evaluate_polynomial,
    feldman_commitments,
    lagrange_coefficient,
    make_shares,
    verify_share,
)
from treasury.vault import (
    decrypt_vault_file,
    derive_file_key,
    elgamal_decrypt,
    elgamal_encrypt,
    encrypt_vault_file,
    open_vault,
    vault_setup,
)


# ---------------------------------------------------------------------------
# sharing.py tests
# ---------------------------------------------------------------------------

class TestEvaluatePolynomial(unittest.TestCase):
    def test_constant(self):
        self.assertEqual(evaluate_polynomial([7], 5, 11), 7)

    def test_linear(self):
        self.assertEqual(evaluate_polynomial([3, 2], 4, 11), (3 + 2 * 4) % 11)

    def test_quadratic(self):
        coeffs = [1, 2, 3]
        x, q = 5, 101
        expected = (1 + 2 * 5 + 3 * 25) % q
        self.assertEqual(evaluate_polynomial(coeffs, x, q), expected)

    def test_at_zero_returns_constant(self):
        self.assertEqual(evaluate_polynomial([42, 7, 13], 0, 1_000_003), 42)

    def test_modular_reduction(self):
        result = evaluate_polynomial([100, 100], 100, 7)
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, 7)


class TestMakeShares(unittest.TestCase):
    def test_basic_3_of_5(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(s, 3, 5, Q)
        self.assertEqual(len(coeffs), 3)
        self.assertEqual(len(shares), 5)
        self.assertEqual(coeffs[0], s)

    def test_reconstruction_3_of_5(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        selected = [1, 3, 5]
        recon = sum(
            shares[i - 1] * lagrange_coefficient(i, selected, Q) % Q
            for i in selected
        ) % Q
        self.assertEqual(recon, s)

    def test_reconstruction_all_combos(self):
        from itertools import combinations
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        for combo in combinations([1, 2, 3, 4, 5], 3):
            recon = sum(
                shares[i - 1] * lagrange_coefficient(i, list(combo), Q) % Q
                for i in combo
            ) % Q
            self.assertEqual(recon, s, f"Failed for combo {combo}")

    def test_configurable_t_n(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(s, 2, 4, Q)
        self.assertEqual(len(coeffs), 2)
        self.assertEqual(len(shares), 4)

    def test_invalid_t_n(self):
        with self.assertRaises(ValueError):
            make_shares(42, 4, 3, Q)   # t > n


class TestFeldmanCommitments(unittest.TestCase):
    def test_length(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, _ = make_shares(s, 3, 5, Q)
        comms = feldman_commitments(coeffs, P, G)
        self.assertEqual(len(comms), len(coeffs))

    def test_first_commitment_is_vault_key(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, _ = make_shares(s, 3, 5, Q)
        comms = feldman_commitments(coeffs, P, G)
        self.assertEqual(comms[0], pow(G, s, P))


class TestVerifyShare(unittest.TestCase):
    def test_valid_share_passes(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(s, 3, 5, Q)
        comms = feldman_commitments(coeffs, P, G)
        for i in range(5):
            self.assertTrue(verify_share(shares[i], i + 1, comms, P, Q, G),
                            f"share {i+1} failed")

    def test_corrupted_share_fails(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(s, 3, 5, Q)
        comms = feldman_commitments(coeffs, P, G)
        bad = (shares[0] + 1) % Q
        self.assertFalse(verify_share(bad, 1, comms, P, Q, G))


class TestLagrangeCoefficient(unittest.TestCase):
    def test_single_member_gives_one(self):
        lam = lagrange_coefficient(1, [1], Q)
        self.assertEqual(lam, 1)

    def test_coefficients_sum_correctly(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        selected = [1, 2, 3]
        recon = 0
        for i in selected:
            lam = lagrange_coefficient(i, selected, Q)
            recon = (recon + shares[i - 1] * lam) % Q
        self.assertEqual(recon, s)


# ---------------------------------------------------------------------------
# opening.py tests
# ---------------------------------------------------------------------------

class TestMakeDecryptionShare(unittest.TestCase):
    def _setup(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        r = secrets.randbelow(Q - 1) + 1
        c1 = pow(G, r, P)
        return s, shares, c1, r

    def test_returns_required_fields(self):
        _, shares, c1, _ = self._setup()
        contrib = make_decryption_share(shares[0], 1, c1)
        for field in ("member_index", "d_i", "V_i", "a1", "a2", "c", "z"):
            self.assertIn(field, contrib, f"missing field: {field}")

    def test_proof_verifies(self):
        _, shares, c1, _ = self._setup()
        contrib = make_decryption_share(shares[0], 1, c1)
        self.assertTrue(verify_decryption_share(contrib, c1))

    def test_all_five_proofs_verify(self):
        _, shares, c1, _ = self._setup()
        for i in range(5):
            contrib = make_decryption_share(shares[i], i + 1, c1)
            self.assertTrue(verify_decryption_share(contrib, c1),
                            f"proof failed for member {i+1}")


class TestVerifyDecryptionShare(unittest.TestCase):
    def _make_valid_contrib(self, si, idx, c1):
        return make_decryption_share(si, idx, c1)

    def test_valid_proof_accepted(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        c1 = pow(G, secrets.randbelow(Q - 1) + 1, P)
        contrib = self._make_valid_contrib(shares[0], 1, c1)
        self.assertTrue(verify_decryption_share(contrib, c1))

    def test_tampered_d_i_rejected(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        c1 = pow(G, secrets.randbelow(Q - 1) + 1, P)
        contrib = self._make_valid_contrib(shares[0], 1, c1)
        d_bad = (int(contrib["d_i"], 16) + 1) % P
        contrib["d_i"] = format(d_bad, "x")
        self.assertFalse(verify_decryption_share(contrib, c1))

    def test_tampered_z_rejected(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        c1 = pow(G, secrets.randbelow(Q - 1) + 1, P)
        contrib = self._make_valid_contrib(shares[0], 1, c1)
        z_bad = (int(contrib["z"], 16) + 1) % Q
        contrib["z"] = format(z_bad, "x")
        self.assertFalse(verify_decryption_share(contrib, c1))

    def test_weak_no_proof_accepts_anything(self):
        """A5: weak mode must accept even a completely invalid contribution."""
        bad_contrib = {
            "member_index": 1,
            "d_i": "deadbeef",
            "V_i": "cafebabe",
            "a1": "00000001",
            "a2": "00000001",
            "c":  "00000001",
            "z":  "00000001",
        }
        self.assertTrue(verify_decryption_share(bad_contrib, 42, weak="no-proof"))

    def test_missing_fields_rejected(self):
        self.assertFalse(verify_decryption_share({}, 42))

    def test_malformed_hex_rejected(self):
        contrib = {
            "member_index": 1, "d_i": "ZZZZ", "V_i": "aa",
            "a1": "aa", "a2": "aa", "c": "aa", "z": "aa",
        }
        self.assertFalse(verify_decryption_share(contrib, 42))


class TestCombineDecryptionShares(unittest.TestCase):
    def _full_setup(self, t=3, n=5):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, t, n, Q)
        r = secrets.randbelow(Q - 1) + 1
        c1 = pow(G, r, P)
        H_vault = pow(G, s, P)
        e = secrets.randbelow(Q - 1) + 1
        e_elem = pow(G, e, P)
        c2 = (e_elem * pow(H_vault, r, P)) % P
        return s, shares, c1, c2, e_elem

    def test_combination_recovers_correct_element(self):
        s, shares, c1, c2, e_elem = self._full_setup()
        contributions = [make_decryption_share(shares[i], i + 1, c1) for i in range(5)]
        combined = combine_decryption_shares(contributions[:3], c1, 3)
        self.assertIsNotNone(combined)
        combined_inv = pow(combined, P - 2, P)
        recovered = (c2 * combined_inv) % P
        self.assertEqual(recovered, e_elem)

    def test_fewer_than_threshold_returns_none(self):
        s, shares, c1, _, _ = self._full_setup()
        contributions = [make_decryption_share(shares[i], i + 1, c1) for i in range(2)]
        result = combine_decryption_shares(contributions, c1, 3)
        self.assertIsNone(result)

    def test_cheating_member_rejected_in_secure_mode(self):
        """A5 secure: a corrupted contribution is rejected; vault still opens."""
        s, shares, c1, c2, e_elem = self._full_setup()
        valid_contribs = [make_decryption_share(shares[i], i + 1, c1) for i in range(4)]
        bad_si = (shares[4] + 1) % Q
        cheat = make_decryption_share(bad_si, 5, c1)
        all_contribs = valid_contribs + [cheat]
        combined = combine_decryption_shares(all_contribs, c1, 3, weak=None)
        self.assertIsNotNone(combined)
        combined_inv = pow(combined, P - 2, P)
        recovered = (c2 * combined_inv) % P
        self.assertEqual(recovered, e_elem)

    def test_cheating_member_accepted_in_weak_mode(self):
        """A5 weak: cheating contribution passes verification."""
        s, shares, c1, c2, _ = self._full_setup()
        bad_si = (shares[0] + 1) % Q
        cheat = make_decryption_share(bad_si, 1, c1)
        self.assertTrue(verify_decryption_share(cheat, c1, weak="no-proof"))


# ---------------------------------------------------------------------------
# vault.py tests
# ---------------------------------------------------------------------------

class TestElGamal(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        s = secrets.randbelow(Q - 1) + 1
        H = pow(G, s, P)
        m = pow(G, secrets.randbelow(Q - 1) + 1, P)
        c1, c2 = elgamal_encrypt(m, H)
        recovered = elgamal_decrypt(c1, c2, s)
        self.assertEqual(recovered, m)

    def test_ciphertext_randomises(self):
        s = secrets.randbelow(Q - 1) + 1
        H = pow(G, s, P)
        m = pow(G, 7, P)
        c1a, c2a = elgamal_encrypt(m, H)
        c1b, c2b = elgamal_encrypt(m, H)
        self.assertNotEqual((c1a, c2a), (c1b, c2b))


class TestAESGCM(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        key = secrets.token_bytes(32)
        plaintext = b"secret vault content"
        enc = encrypt_vault_file(plaintext, key)
        dec = decrypt_vault_file(enc, key)
        self.assertEqual(dec, plaintext)

    def test_wrong_key_raises(self):
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        enc = encrypt_vault_file(b"data", key1)
        with self.assertRaises(ValueError):
            decrypt_vault_file(enc, key2)

    def test_tampered_ciphertext_raises(self):
        key = secrets.token_bytes(32)
        enc = encrypt_vault_file(b"important", key)
        ct = bytearray.fromhex(enc["ciphertext"])
        ct[0] ^= 0xFF
        enc["ciphertext"] = ct.hex()
        with self.assertRaises(ValueError):
            decrypt_vault_file(enc, key)


class TestHKDF(unittest.TestCase):
    def test_deterministic_given_same_inputs(self):
        element = pow(G, 42, P)
        salt = b"\x00" * 32
        k1 = derive_file_key(element, salt)
        k2 = derive_file_key(element, salt)
        self.assertEqual(k1, k2)

    def test_different_elements_give_different_keys(self):
        salt = b"\x00" * 32
        k1 = derive_file_key(pow(G, 42, P), salt)
        k2 = derive_file_key(pow(G, 43, P), salt)
        self.assertNotEqual(k1, k2)

    def test_key_is_32_bytes(self):
        k = derive_file_key(pow(G, 1, P), b"\x00" * 32)
        self.assertEqual(len(k), 32)


class TestVaultSetupAndOpen(unittest.TestCase):
    """Integration test: full vault lifecycle with a temporary directory."""

    def _init_data_dir(self, tmp_path: Path, n: int = 5) -> None:
        from treasury.config import member_names
        for name in member_names(n):
            (tmp_path / name).mkdir(parents=True, exist_ok=True, mode=0o700)
        (tmp_path / "public").mkdir(parents=True, exist_ok=True)

    def test_vault_setup_creates_files(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._init_data_dir(tmp)
            content = b"My secret vault content"
            pub = vault_setup(tmp, 3, 5, content)
            self.assertTrue((tmp / "public" / "vault_public.json").exists())
            from treasury.config import member_names
            for name in member_names(5):
                self.assertTrue((tmp / name / "share.json").exists(),
                                f"{name}/share.json missing")
            for key in ("commitments", "vault_key", "V_keys", "elgamal", "encrypted_vault"):
                self.assertIn(key, pub)

    def test_full_vault_open_3_of_5(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._init_data_dir(tmp)
            content = b"Treasury ledger data - confidential"
            vault_public = vault_setup(tmp, 3, 5, content)
            c1 = int(vault_public["elgamal"]["c1"], 16)

            from treasury.config import member_names
            from treasury.vault import load_member_share
            contributions = []
            for i, name in enumerate(member_names(5)):
                sd = load_member_share(tmp, name)
                si  = int(sd["share"], 16)
                V_i = int(sd["V_i"],   16)
                contrib = make_decryption_share(si, i + 1, c1, verification_key=V_i)
                contributions.append(contrib)

            result = open_vault(vault_public, contributions[:3])
            self.assertEqual(result, content)

    def test_vault_open_with_all_5_still_works(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._init_data_dir(tmp)
            content = b"All five members contribute"
            vault_public = vault_setup(tmp, 3, 5, content)
            c1 = int(vault_public["elgamal"]["c1"], 16)

            from treasury.config import member_names
            from treasury.vault import load_member_share
            contributions = []
            for i, name in enumerate(member_names(5)):
                sd = load_member_share(tmp, name)
                si  = int(sd["share"], 16)
                V_i = int(sd["V_i"],   16)
                contrib = make_decryption_share(si, i + 1, c1, verification_key=V_i)
                contributions.append(contrib)

            result = open_vault(vault_public, contributions)
            self.assertEqual(result, content)

    def test_vault_open_fails_with_2_contributions(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._init_data_dir(tmp)
            content = b"Should not open"
            vault_public = vault_setup(tmp, 3, 5, content)
            c1 = int(vault_public["elgamal"]["c1"], 16)

            from treasury.config import member_names
            from treasury.vault import load_member_share
            contributions = []
            for i, name in enumerate(list(member_names(5))[:2]):
                sd = load_member_share(tmp, name)
                si  = int(sd["share"], 16)
                V_i = int(sd["V_i"],   16)
                contrib = make_decryption_share(si, i + 1, c1, verification_key=V_i)
                contributions.append(contrib)

            result = open_vault(vault_public, contributions)
            self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Attack A5: Cheating Member demonstration
# ---------------------------------------------------------------------------

class TestAttackA5(unittest.TestCase):
    """Demonstrate weak vs secure mode for a cheating member."""

    def _setup_vault(self, tmp):
        from treasury.config import member_names
        (tmp / "public").mkdir(parents=True, exist_ok=True)
        for name in member_names(5):
            (tmp / name).mkdir(parents=True, exist_ok=True, mode=0o700)
        content = b"Attack A5 test vault"
        return vault_setup(tmp, 3, 5, content), content

    def _get_contributions(self, tmp, vault_public, cheat_index=None):
        from treasury.config import member_names
        from treasury.vault import load_member_share
        c1 = int(vault_public["elgamal"]["c1"], 16)
        contributions = []
        for i, name in enumerate(member_names(5)):
            sd = load_member_share(tmp, name)
            si  = int(sd["share"], 16)
            V_i = int(sd["V_i"],   16)
            if cheat_index is not None and i + 1 == cheat_index:
                bad_si = (si + 42) % Q
                contrib = make_decryption_share(bad_si, i + 1, c1,
                                                verification_key=V_i)
            else:
                contrib = make_decryption_share(si, i + 1, c1,
                                                verification_key=V_i)
            contributions.append(contrib)
        return contributions

    def test_a5_secure_mode_rejects_cheater_vault_still_opens(self):
        """Secure mode: cheater rejected; 4 valid remain → vault opens."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vault_public, content = self._setup_vault(tmp)
            contributions = self._get_contributions(tmp, vault_public, cheat_index=2)
            result = open_vault(vault_public, contributions, weak=None)
            self.assertEqual(result, content)

    def test_a5_weak_mode_cheater_causes_wrong_decryption(self):
        """Weak mode: cheater's invalid d_i corrupts the decryption."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vault_public, content = self._setup_vault(tmp)

            from treasury.config import member_names
            from treasury.vault import load_member_share
            c1 = int(vault_public["elgamal"]["c1"], 16)
            contributions = []
            for i, name in enumerate(list(member_names(5))[:3]):
                sd = load_member_share(tmp, name)
                si  = int(sd["share"], 16)
                V_i = int(sd["V_i"],   16)
                if i + 1 == 2:
                    bad_si = (si + 42) % Q
                    contrib = make_decryption_share(bad_si, i + 1, c1,
                                                    verification_key=V_i)
                else:
                    contrib = make_decryption_share(si, i + 1, c1,
                                                    verification_key=V_i)
                contributions.append(contrib)

            result = open_vault(vault_public, contributions, weak="no-proof")
            self.assertNotEqual(result, content)


if __name__ == "__main__":
    unittest.main()
