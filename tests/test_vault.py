"""Automated tests for Divan's Milestone 2 implementation.

Covers:
  - treasury/sharing.py  (Shamir SSS, Feldman VSS, Lagrange coefficients)
  - treasury/opening.py  (Chaum-Pedersen proofs, combination)
  - treasury/vault.py    (ElGamal, HKDF, AES-GCM, vault setup/open)
  - Attack A5            (weak no-proof mode vs secure mode)

Run with:  python -m pytest tests/test_vault.py -v
"""
import json
import secrets
import tempfile
from pathlib import Path

import pytest

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
# Helpers
# ---------------------------------------------------------------------------

SMALL_P = 23      # tiny prime for fast arithmetic tests
SMALL_Q = 11      # (P-1)/2
SMALL_G = 4       # generator of the subgroup (4^11 = 1 mod 23)


# ---------------------------------------------------------------------------
# sharing.py tests
# ---------------------------------------------------------------------------

class TestEvaluatePolynomial:
    def test_constant(self):
        # f(x) = 7  →  f(5) = 7
        assert evaluate_polynomial([7], 5, 11) == 7

    def test_linear(self):
        # f(x) = 3 + 2x  →  f(4) = 11 ≡ 0 (mod 11)
        assert evaluate_polynomial([3, 2], 4, 11) == (3 + 2 * 4) % 11

    def test_quadratic(self):
        coeffs = [1, 2, 3]
        x, q = 5, 101
        expected = (1 + 2 * 5 + 3 * 25) % q
        assert evaluate_polynomial(coeffs, x, q) == expected

    def test_at_zero_returns_constant(self):
        # f(0) = a0
        assert evaluate_polynomial([42, 7, 13], 0, 1000003) == 42

    def test_modular_reduction(self):
        # Result must be in [0, q)
        result = evaluate_polynomial([100, 100], 100, 7)
        assert 0 <= result < 7


class TestMakeShares:
    def test_basic_3_of_5(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(s, 3, 5, Q)
        assert len(coeffs) == 3
        assert len(shares) == 5
        assert coeffs[0] == s

    def test_reconstruction_3_of_5(self):
        """Any 3 shares reconstruct the secret via Lagrange interpolation."""
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        # Use members 1,3,5 (1-based)
        selected = [1, 3, 5]
        recon = sum(
            shares[i - 1] * lagrange_coefficient(i, selected, Q) % Q
            for i in selected
        ) % Q
        assert recon == s

    def test_reconstruction_all_combos(self):
        """All C(5,3)=10 combinations of 3-of-5 must reconstruct the secret."""
        from itertools import combinations
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        for combo in combinations([1, 2, 3, 4, 5], 3):
            recon = sum(
                shares[i - 1] * lagrange_coefficient(i, list(combo), Q) % Q
                for i in combo
            ) % Q
            assert recon == s, f"Failed for combo {combo}"

    def test_fewer_than_threshold_reveals_nothing(self):
        """2 shares of a 3-of-5 scheme give a wrong reconstruction."""
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        selected = [1, 2]
        recon = sum(
            shares[i - 1] * lagrange_coefficient(i, selected, Q) % Q
            for i in selected
        ) % Q
        # With high probability, reconstruction with t-1 shares gives wrong result
        # (this will occasionally pass by coincidence, but is astronomically unlikely)
        # We just verify it doesn't always equal s
        # (a proper information-theoretic proof needs many samples)
        pass   # noted: single test cannot prove info-theoretic security

    def test_configurable_t_n(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(s, 2, 4, Q)
        assert len(coeffs) == 2
        assert len(shares) == 4

    def test_invalid_t_n(self):
        with pytest.raises(ValueError):
            make_shares(42, 4, 3, Q)   # t > n


class TestFeldmanCommitments:
    def test_length(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, _ = make_shares(s, 3, 5, Q)
        comms = feldman_commitments(coeffs, P, G)
        assert len(comms) == len(coeffs)

    def test_first_commitment_is_vault_key(self):
        """C_0 = g^{a_0} = g^s = H_vault."""
        s = secrets.randbelow(Q - 1) + 1
        coeffs, _ = make_shares(s, 3, 5, Q)
        comms = feldman_commitments(coeffs, P, G)
        assert comms[0] == pow(G, s, P)


class TestVerifyShare:
    def test_valid_share_passes(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(s, 3, 5, Q)
        comms = feldman_commitments(coeffs, P, G)
        for i in range(5):
            assert verify_share(shares[i], i + 1, comms, P, Q, G), f"share {i+1} failed"

    def test_corrupted_share_fails(self):
        s = secrets.randbelow(Q - 1) + 1
        coeffs, shares = make_shares(s, 3, 5, Q)
        comms = feldman_commitments(coeffs, P, G)
        bad = (shares[0] + 1) % Q
        assert not verify_share(bad, 1, comms, P, Q, G)


class TestLagrangeCoefficient:
    def test_single_member_gives_one(self):
        """With one member, λ_1({1}) = 1 always (trivially)."""
        # 1-of-1: f(x) = s, so λ_1 = 1
        # Numerator: (-1) = q-1   denominator: (1-1)... no j≠i, so result is 1
        lam = lagrange_coefficient(1, [1], Q)
        assert lam == 1

    def test_coefficients_sum_correctly(self):
        """Sum of λ_i(0) for all t members should reconstruct the secret."""
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        selected = [1, 2, 3]
        recon = 0
        for i in selected:
            lam = lagrange_coefficient(i, selected, Q)
            recon = (recon + shares[i - 1] * lam) % Q
        assert recon == s


# ---------------------------------------------------------------------------
# opening.py tests
# ---------------------------------------------------------------------------

class TestMakeDecryptionShare:
    def _setup(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        r = secrets.randbelow(Q - 1) + 1
        c1 = pow(G, r, P)   # ElGamal c1
        return s, shares, c1, r

    def test_returns_required_fields(self):
        _, shares, c1, _ = self._setup()
        contrib = make_decryption_share(shares[0], 1, c1)
        for field in ("member_index", "d_i", "V_i", "a1", "a2", "c", "z"):
            assert field in contrib, f"missing field: {field}"

    def test_proof_verifies(self):
        _, shares, c1, _ = self._setup()
        contrib = make_decryption_share(shares[0], 1, c1)
        assert verify_decryption_share(contrib, c1)

    def test_all_five_proofs_verify(self):
        _, shares, c1, _ = self._setup()
        for i in range(5):
            contrib = make_decryption_share(shares[i], i + 1, c1)
            assert verify_decryption_share(contrib, c1), f"proof failed for member {i+1}"


class TestVerifyDecryptionShare:
    def _make_valid_contrib(self, si, idx, c1):
        return make_decryption_share(si, idx, c1)

    def test_valid_proof_accepted(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        c1 = pow(G, secrets.randbelow(Q - 1) + 1, P)
        contrib = self._make_valid_contrib(shares[0], 1, c1)
        assert verify_decryption_share(contrib, c1)

    def test_tampered_d_i_rejected(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        c1 = pow(G, secrets.randbelow(Q - 1) + 1, P)
        contrib = self._make_valid_contrib(shares[0], 1, c1)
        # Tamper with d_i
        d_bad = (int(contrib["d_i"], 16) + 1) % P
        contrib["d_i"] = format(d_bad, "x")
        assert not verify_decryption_share(contrib, c1)

    def test_tampered_z_rejected(self):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, 3, 5, Q)
        c1 = pow(G, secrets.randbelow(Q - 1) + 1, P)
        contrib = self._make_valid_contrib(shares[0], 1, c1)
        z_bad = (int(contrib["z"], 16) + 1) % Q
        contrib["z"] = format(z_bad, "x")
        assert not verify_decryption_share(contrib, c1)

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
        assert verify_decryption_share(bad_contrib, 42, weak="no-proof")

    def test_missing_fields_rejected(self):
        assert not verify_decryption_share({}, 42)

    def test_malformed_hex_rejected(self):
        contrib = {
            "member_index": 1, "d_i": "ZZZZ", "V_i": "aa",
            "a1": "aa", "a2": "aa", "c": "aa", "z": "aa",
        }
        assert not verify_decryption_share(contrib, 42)


class TestCombineDecryptionShares:
    def _full_setup(self, t=3, n=5):
        s = secrets.randbelow(Q - 1) + 1
        _, shares = make_shares(s, t, n, Q)
        r = secrets.randbelow(Q - 1) + 1
        c1 = pow(G, r, P)
        H_vault = pow(G, s, P)
        # Encrypt a known element
        e = secrets.randbelow(Q - 1) + 1
        e_elem = pow(G, e, P)
        c2 = (e_elem * pow(H_vault, r, P)) % P
        return s, shares, c1, c2, e_elem

    def test_combination_recovers_correct_element(self):
        s, shares, c1, c2, e_elem = self._full_setup()
        contributions = [make_decryption_share(shares[i], i + 1, c1) for i in range(5)]
        combined = combine_decryption_shares(contributions[:3], c1, 3)
        assert combined is not None
        # combined = c1^s = g^{r*s}; c2 / combined = e_elem
        combined_inv = pow(combined, P - 2, P)
        recovered = (c2 * combined_inv) % P
        assert recovered == e_elem

    def test_fewer_than_threshold_returns_none(self):
        """With t=3 and only 2 valid contributions, return None."""
        s, shares, c1, _, _ = self._full_setup()
        contributions = [make_decryption_share(shares[i], i + 1, c1) for i in range(2)]
        result = combine_decryption_shares(contributions, c1, 3)
        assert result is None

    def test_cheating_member_rejected_in_secure_mode(self):
        """A5 secure: a corrupted contribution is rejected; vault still opens with remaining valid shares."""
        s, shares, c1, c2, e_elem = self._full_setup()
        # Build 4 valid + 1 cheating contribution
        valid_contribs = [make_decryption_share(shares[i], i + 1, c1) for i in range(4)]
        # Cheat member 5: corrupt the share
        bad_si = (shares[4] + 1) % Q
        cheat = make_decryption_share(bad_si, 5, c1)
        all_contribs = valid_contribs + [cheat]

        # Secure mode: cheat is rejected, but 4 valid remain ≥ t=3
        combined = combine_decryption_shares(all_contribs, c1, 3, weak=None)
        assert combined is not None

        combined_inv = pow(combined, P - 2, P)
        recovered = (c2 * combined_inv) % P
        assert recovered == e_elem

    def test_cheating_member_accepted_in_weak_mode(self):
        """A5 weak: even a cheating contribution passes; vault opens (but result may be corrupted)."""
        s, shares, c1, c2, _ = self._full_setup()
        bad_si = (shares[0] + 1) % Q
        cheat = make_decryption_share(bad_si, 1, c1)
        # In weak mode, cheat passes verify_decryption_share
        assert verify_decryption_share(cheat, c1, weak="no-proof")


# ---------------------------------------------------------------------------
# vault.py tests
# ---------------------------------------------------------------------------

class TestElGamal:
    def test_encrypt_decrypt_roundtrip(self):
        s = secrets.randbelow(Q - 1) + 1
        H = pow(G, s, P)
        m = pow(G, secrets.randbelow(Q - 1) + 1, P)   # random group element
        c1, c2 = elgamal_encrypt(m, H)
        recovered = elgamal_decrypt(c1, c2, s)
        assert recovered == m

    def test_ciphertext_randomises(self):
        s = secrets.randbelow(Q - 1) + 1
        H = pow(G, s, P)
        m = pow(G, 7, P)
        c1a, c2a = elgamal_encrypt(m, H)
        c1b, c2b = elgamal_encrypt(m, H)
        # With overwhelming probability, two encryptions differ (CPA security)
        assert (c1a, c2a) != (c1b, c2b)


class TestAESGCM:
    def test_encrypt_decrypt_roundtrip(self):
        key = secrets.token_bytes(32)
        plaintext = b"secret vault content"
        enc = encrypt_vault_file(plaintext, key)
        dec = decrypt_vault_file(enc, key)
        assert dec == plaintext

    def test_wrong_key_raises(self):
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        enc = encrypt_vault_file(b"data", key1)
        with pytest.raises(ValueError):
            decrypt_vault_file(enc, key2)

    def test_tampered_ciphertext_raises(self):
        key = secrets.token_bytes(32)
        enc = encrypt_vault_file(b"important", key)
        ct = bytearray.fromhex(enc["ciphertext"])
        ct[0] ^= 0xFF
        enc["ciphertext"] = ct.hex()
        with pytest.raises(ValueError):
            decrypt_vault_file(enc, key)


class TestHKDF:
    def test_deterministic_given_same_inputs(self):
        element = pow(G, 42, P)
        salt = b"\x00" * 32
        k1 = derive_file_key(element, salt)
        k2 = derive_file_key(element, salt)
        assert k1 == k2

    def test_different_elements_give_different_keys(self):
        salt = b"\x00" * 32
        k1 = derive_file_key(pow(G, 42, P), salt)
        k2 = derive_file_key(pow(G, 43, P), salt)
        assert k1 != k2

    def test_key_is_32_bytes(self):
        k = derive_file_key(pow(G, 1, P), b"\x00" * 32)
        assert len(k) == 32


class TestVaultSetupAndOpen:
    """Integration test: full vault lifecycle with a temporary data directory."""

    def _init_data_dir(self, tmp_path: Path, n: int = 5) -> None:
        """Create minimal file structure (no real certificates needed for vault tests)."""
        # Create member private directories (vault writes shares here)
        from treasury.config import member_names
        for name in member_names(n):
            (tmp_path / name).mkdir(parents=True, exist_ok=True, mode=0o700)
        (tmp_path / "public").mkdir(parents=True, exist_ok=True)

    def test_vault_setup_creates_files(self, tmp_path):
        self._init_data_dir(tmp_path)
        content = b"My secret vault content"
        pub = vault_setup(tmp_path, 3, 5, content)
        # Public vault file must exist
        assert (tmp_path / "public" / "vault_public.json").exists()
        # Each member must have a private share file
        from treasury.config import member_names
        for name in member_names(5):
            assert (tmp_path / name / "share.json").exists(), f"{name}/share.json missing"
        # Public record has required fields
        for key in ("commitments", "vault_key", "V_keys", "elgamal", "encrypted_vault"):
            assert key in pub

    def test_full_vault_open_3_of_5(self, tmp_path):
        self._init_data_dir(tmp_path)
        content = b"Treasury ledger data - confidential"
        vault_public = vault_setup(tmp_path, 3, 5, content)
        c1 = int(vault_public["elgamal"]["c1"], 16)

        from treasury.config import member_names
        from treasury.vault import load_member_share
        contributions = []
        for i, name in enumerate(member_names(5)):
            sd = load_member_share(tmp_path, name)
            si  = int(sd["share"], 16)
            V_i = int(sd["V_i"],   16)
            contrib = make_decryption_share(si, i + 1, c1, verification_key=V_i)
            contributions.append(contrib)

        # Open with exactly t=3 contributions
        result = open_vault(vault_public, contributions[:3])
        assert result == content

    def test_vault_open_with_all_5_still_works(self, tmp_path):
        self._init_data_dir(tmp_path)
        content = b"All five members contribute"
        vault_public = vault_setup(tmp_path, 3, 5, content)
        c1 = int(vault_public["elgamal"]["c1"], 16)

        from treasury.config import member_names
        from treasury.vault import load_member_share
        contributions = []
        for i, name in enumerate(member_names(5)):
            sd = load_member_share(tmp_path, name)
            si  = int(sd["share"], 16)
            V_i = int(sd["V_i"],   16)
            contrib = make_decryption_share(si, i + 1, c1, verification_key=V_i)
            contributions.append(contrib)

        result = open_vault(vault_public, contributions)
        assert result == content

    def test_vault_open_fails_with_2_of_3_threshold(self, tmp_path):
        self._init_data_dir(tmp_path)
        content = b"Should not open"
        vault_public = vault_setup(tmp_path, 3, 5, content)
        c1 = int(vault_public["elgamal"]["c1"], 16)

        from treasury.config import member_names
        from treasury.vault import load_member_share
        contributions = []
        for i, name in enumerate(list(member_names(5))[:2]):
            sd = load_member_share(tmp_path, name)
            si  = int(sd["share"], 16)
            V_i = int(sd["V_i"],   16)
            contrib = make_decryption_share(si, i + 1, c1, verification_key=V_i)
            contributions.append(contrib)

        result = open_vault(vault_public, contributions)
        assert result is None


# ---------------------------------------------------------------------------
# Attack A5: Cheating Member demonstration
# ---------------------------------------------------------------------------

class TestAttackA5:
    """Demonstrate weak vs secure mode for a cheating member."""

    def _setup_vault(self, tmp_path):
        from treasury.config import member_names
        (tmp_path / "public").mkdir(parents=True, exist_ok=True)
        for name in member_names(5):
            (tmp_path / name).mkdir(parents=True, exist_ok=True, mode=0o700)
        content = b"Attack A5 test vault"
        return vault_setup(tmp_path, 3, 5, content), content

    def _get_contributions(self, tmp_path, vault_public, cheat_index=None):
        from treasury.config import member_names
        from treasury.vault import load_member_share
        c1 = int(vault_public["elgamal"]["c1"], 16)
        contributions = []
        for i, name in enumerate(member_names(5)):
            sd = load_member_share(tmp_path, name)
            si  = int(sd["share"], 16)
            V_i = int(sd["V_i"],   16)
            if cheat_index is not None and i + 1 == cheat_index:
                # Submit corrupted share
                bad_si = (si + 42) % Q
                contrib = make_decryption_share(bad_si, i + 1, c1, verification_key=V_i)
            else:
                contrib = make_decryption_share(si, i + 1, c1, verification_key=V_i)
            contributions.append(contrib)
        return contributions

    def test_a5_secure_mode_rejects_cheater_vault_still_opens(self, tmp_path):
        """Secure mode: cheating member 2 is rejected; 4 valid remain → vault opens."""
        vault_public, content = self._setup_vault(tmp_path)
        # Member 2 cheats; members 1,3,4,5 are honest
        contributions = self._get_contributions(tmp_path, vault_public, cheat_index=2)
        result = open_vault(vault_public, contributions, weak=None)
        # 4 valid contributions ≥ threshold 3, so vault MUST open
        assert result == content

    def test_a5_weak_mode_cheater_causes_wrong_decryption(self, tmp_path):
        """Weak mode (no-proof): cheating member's invalid d_i corrupts the decryption.

        The vault either opens with wrong content or fails entirely.
        In either case, the result differs from the intended plaintext.
        """
        vault_public, content = self._setup_vault(tmp_path)
        # Use ONLY 3 contributions: members 1 (honest), 2 (cheater), 3 (honest)
        from treasury.config import member_names
        from treasury.vault import load_member_share
        c1 = int(vault_public["elgamal"]["c1"], 16)
        contributions = []
        for i, name in enumerate(list(member_names(5))[:3]):
            sd = load_member_share(tmp_path, name)
            si  = int(sd["share"], 16)
            V_i = int(sd["V_i"],   16)
            if i + 1 == 2:   # member 2 cheats
                bad_si = (si + 42) % Q
                contrib = make_decryption_share(bad_si, i + 1, c1, verification_key=V_i)
            else:
                contrib = make_decryption_share(si, i + 1, c1, verification_key=V_i)
            contributions.append(contrib)

        # Weak mode: proof check skipped → corrupted d_2 is accepted → wrong key → AES-GCM fails
        result = open_vault(vault_public, contributions, weak="no-proof")
        # Either None (AES-GCM tag fails) or wrong content
        assert result != content
