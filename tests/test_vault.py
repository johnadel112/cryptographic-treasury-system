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




# Regressions replace the old tests that trusted a contributor's self-declared V_i.
import copy
import pytest
from conftest import client
from treasury.identity import load_identity
from treasury.vault import check_vault_public, load_member_share, trusted_verification_keys
from treasury.encoding import H, canonical_json


def test_signed_commitments_and_tamper(env):
    root,port,app=env
    founder=load_identity("M1",root).founder_public_key
    check_vault_public(app.vault,founder)
    bad=copy.deepcopy(app.vault)
    bad["commitments"][0]=format(pow(G,99,P),"x")
    with pytest.raises(ValueError):check_vault_public(bad,founder)


def test_exact_proof_transcript_and_trusted_key(env):
    root,port,app=env
    share=int(load_member_share(root,"M1")["share"],16)
    c1=int(app.vault["elgamal"]["c1"],16)
    proof=make_decryption_share(share,1,c1)
    hi=app.keys[1]
    assert verify_decryption_share(proof,c1,verification_key=hi,member_index=1)
    e=H("dec",1,c1,hi,int(proof["d_i"],16),int(proof["T1"],16),int(proof["T2"],16),q=Q)
    assert pow(G,int(proof["z"],16),P)==int(proof["T1"],16)*pow(hi,e,P)%P
    # A fully self-consistent proof of an attacker-selected share is still rejected.
    forged=make_decryption_share(123,1,c1)
    assert not verify_decryption_share(forged,c1,verification_key=hi,member_index=1)
    assert not verify_decryption_share(proof,c1,verification_key=hi,member_index=2)
    assert not verify_decryption_share(proof,pow(G,71,P),verification_key=hi,member_index=1)
    bad=dict(proof,z=format(Q,"x"))
    assert not verify_decryption_share(bad,c1,verification_key=hi,member_index=1)


def test_duplicate_contributions_do_not_reach_threshold(env):
    root,port,app=env
    c1=int(app.vault["elgamal"]["c1"],16)
    proof=make_decryption_share(int(load_member_share(root,"M1")["share"],16),1,c1)
    assert combine_decryption_shares([proof]*3,c1,3,verification_keys=app.keys) is None


@pytest.mark.parametrize("members", [("M1","M3","M5"),("M2","M4","M5")])
def test_network_vault_alternative_combinations(env,members):
    root,port,app=env
    opener=client(root,port)
    operation=opener.request("open-vault",{})["result"]["id"]
    opener.close()
    for index,name in enumerate(members):
        c=client(root,port,name)
        result=c.contribute(operation)
        c.close()
        assert result["ok"]
        assert result["result"]["state"]==("opened" if index==2 else "collecting")
    assert bytes.fromhex(result["result"]["content_hex"])==b"integrated treasury treasure"


def test_share_complaint_and_no_participation(env):
    import json
    root,port,app=env
    c=client(root,port)
    operation=c.request("open-vault",{})["result"]["id"]
    path=root/"M1"/"share.json"
    share=json.loads(path.read_text())
    share["share"]=format((int(share["share"],16)+1)%Q,"x")
    path.write_text(json.dumps(share))
    assert not c.contribute(operation)["ok"]
    c.close()
    state=app.store.snapshot()
    assert state["ledger"][-1]["op"]=="share-complaint"
    assert state["operations"][operation]["contributions"]=={}


def test_duplicate_unknown_and_cross_operation_replay(env):
    root,port,app=env
    c=client(root,port)
    one=c.request("open-vault",{})["result"]["id"]
    two=c.request("open-vault",{})["result"]["id"]
    proof=make_decryption_share(int(load_member_share(root,"M1")["share"],16),1,int(app.vault["elgamal"]["c1"],16))
    assert c.request("contribute",{"operation":one,"proof":proof})["ok"]
    assert not c.request("contribute",{"operation":one,"proof":proof})["ok"]
    assert not c.request("contribute",{"operation":two,"proof":proof})["ok"]
    assert not c.request("contribute",{"operation":"missing","proof":proof})["ok"]
    c.close()


@pytest.mark.parametrize("weak", [False,True])
def test_a5_same_M3_corruption_and_substitution(setup_root,service_factory,weak):
    app,port=service_factory(setup_root,["no-proof"] if weak else [])
    c=client(setup_root,port)
    operation=c.request("open-vault",{})["result"]["id"]
    assert c.contribute(operation)["ok"]
    c.close()
    c=client(setup_root,port,"M2");assert c.contribute(operation)["ok"];c.close()
    c=client(setup_root,port,"M3");bad=c.contribute(operation,cheat=True);c.close()
    if weak:
        assert bad["ok"] and bad["result"]["state"]=="failed"
    else:
        assert not bad["ok"]
        c=client(setup_root,port,"M4");result=c.contribute(operation);c.close()
        assert result["result"]["state"]=="opened"


def test_existing_setup_refused_without_changes(env):
    root,port,app=env
    path=root/"public"/"vault_public.json"
    before=path.read_bytes()
    with pytest.raises(ValueError):vault_setup(root,3,5,b"new")
    assert path.read_bytes()==before


def test_server_never_reads_member_private_files(setup_root,service_factory,monkeypatch):
    import threading
    original=Path.open
    root=setup_root.resolve()
    def guarded(path,*args,**kwargs):
        relative=path.resolve().relative_to(root) if path.resolve().is_relative_to(root) else None
        if relative and relative.parts[0].startswith("M") and threading.current_thread() is not threading.main_thread():
            raise AssertionError("server attempted owner-private file access")
        return original(path,*args,**kwargs)
    with monkeypatch.context() as m:
        m.setattr(Path,"open",guarded)
        app,port=service_factory(setup_root)
        assert app.vault["n"]==5
        c=client(setup_root,port)
        operation=c.request("open-vault",{})["result"]["id"]
        assert c.contribute(operation)["ok"]
        c.close()
        for name in ["M3","M5"]:
            c=client(setup_root,port,name);r=c.contribute(operation);c.close()
        assert r["result"]["state"]=="opened"
