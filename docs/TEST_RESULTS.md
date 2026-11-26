# Executed test results

Date: 26 November 2026 (Africa/Cairo). Windows, Python 3.12, cryptography 50.0.2.
Command: `.\.venv-john\Scripts\python.exe -m unittest discover -s tests -v`.
Actual final result: **60 tests, 0 failures, 0 errors, 0 skips**, 9.888 seconds.
This is the executed local run; remote CI and other platform/version results are separate.
All cryptographic operations are real. Process tests start founder, owner initialization,
server, member and Mallory executables with temporary setup files and loopback TCP.
The first two rows include the preserved starter tests. Each expected result below is
checked by assertions in the named test; PASS means those assertions completed.

| Test | Expected result / reason | Actual |
|---|---|---|
| `test_encoding.EncodingTests.test_canonical_json_sorts_keys_and_removes_spaces` | Canonical output has sorted keys and no insignificant spaces. | PASS |
| `test_framing.FramingTests.test_round_trip` | Length-prefixed JSON round-trips across a socket pair. | PASS |
| `test_processes.ProcessTests.test_secure_default_real_processes` | Unflagged processes verify signatures and GCM; normal logs omit probe plaintext. | PASS |
| `test_processes.ProcessTests.test_plaintext_demonstration` | Explicit no-encryption mode retains signed handshake and exchanges plaintext frames. | PASS |
| `test_processes.ProcessTests.test_a1_weak_confidentiality_failure` | Real weak-mode MITM decrypts the probe marker via two ECDH channels. | PASS |
| `test_processes.ProcessTests.test_a1_secure_rejection` | Real member rejects substituted handshake; Mallory receives no application plaintext. | PASS |
| `test_processes.ProcessTests.test_real_replay_rejection` | Transparent proxy repeats ciphertext; server logs expected 1, got 0 and closes. | PASS |
| `test_processes.ProcessTests.test_real_tamper_rejection` | Transparent proxy changes tag; server rejects and member fails. | PASS |
| `test_processes.ProcessTests.test_invalid_member_handshake_signature` | Server closes on invalid final member signature. | PASS |
| `test_processes.ProcessTests.test_missing_member_handshake_signature` | Server closes when the final signature is absent. | PASS |
| `test_processes.ProcessTests.test_malformed_member_handshake_signature` | Server closes on a non-string signature. | PASS |
| `test_processes.ProcessTests.test_weak_member_cannot_downgrade_secure_server` | An unsigned client cannot establish a secure server session. | PASS |
| `test_processes.ProcessTests.test_secure_member_rejects_unsigned_server` | A secure member never accepts the unsigned-handshake server. | PASS |
| `test_processes.ProcessTests.test_network_wrong_group_certificate` | Server rejects foreign GROUP over real TCP. | PASS |
| `test_processes.ProcessTests.test_network_wrong_identity_certificate` | Server rejects unconfigured member identity over real TCP. | PASS |
| `test_processes.ProcessTests.test_network_invalid_founder_certificate` | Server rejects invalid founder signature over real TCP. | PASS |
| `test_processes.ProcessTests.test_network_expired_certificate` | Server rejects expired certificate over real TCP. | PASS |
| `test_processes.ProcessTests.test_network_malformed_frame` | Server rejects zero length and closes cleanly over TCP. | PASS |
| `test_processes.ProcessTests.test_application_operations_fail_closed_until_integration` | Signed-operation-shaped input is refused; login state stays false. | PASS |
| `test_processes.ProcessTests.test_encrypted_non_object_rejected` | Decrypted JSON array is rejected and socket closes. | PASS |
| `test_processes.ProcessTests.test_unexpected_disconnect_during_handshake` | Truncated hello is logged and handled without hanging. | PASS |
| `test_security.CertificateTests.test_exact_format` | Certificate has exactly the five required fields and correct GROUP. | PASS |
| `test_security.CertificateTests.test_valid_certificate` | Founder-signed certificate is accepted. | PASS |
| `test_security.CertificateTests.test_wrong_founder` | Certificate from another founder is rejected. | PASS |
| `test_security.CertificateTests.test_modified_signature` | Changed founder signature is rejected. | PASS |
| `test_security.CertificateTests.test_wrong_group_even_when_signed` | Even a correctly signed foreign GROUP is rejected. | PASS |
| `test_security.CertificateTests.test_wrong_identity` | Certificate for a different expected identity is rejected. | PASS |
| `test_security.CertificateTests.test_expired` | Certificate past its expiry is rejected. | PASS |
| `test_security.CertificateTests.test_expiry_day_is_valid` | Certificate remains valid on its UTC expiry date. | PASS |
| `test_security.CertificateTests.test_missing_and_extra_fields` | Missing or extra certificate fields are rejected. | PASS |
| `test_security.CertificateTests.test_malformed_public_key` | Non-PEM public key is rejected. | PASS |
| `test_security.CertificateTests.test_wrong_curve` | A signed P-384 key is rejected; P-256 is required. | PASS |
| `test_security.CertificateTests.test_invalid_types_and_dates` | Malformed field types, hex and expiry dates are rejected. | PASS |
| `test_security.ChannelTests.test_gcm_roundtrip_and_independent_counters` | Both directions decrypt correctly with independent zero-based counters. | PASS |
| `test_security.ChannelTests.test_ciphertext_tamper_closes_channel` | Changed ciphertext fails tag verification and poisons the channel. | PASS |
| `test_security.ChannelTests.test_tag_tamper` | Changed authentication tag is rejected. | PASS |
| `test_security.ChannelTests.test_replay` | Duplicate nonce fails, and the poisoned channel rejects subsequent frames. | PASS |
| `test_security.ChannelTests.test_skipped_counter` | Receiving nonce 1 before nonce 0 is rejected. | PASS |
| `test_security.ChannelTests.test_invalid_counter` | An altered 96-bit counter is rejected. | PASS |
| `test_security.ChannelTests.test_short_frame` | A truncated nonce/tag frame is rejected. | PASS |
| `test_security.ChannelTests.test_counter_exhaustion` | Last valid nonce works; overflow closes the channel. | PASS |
| `test_security.ChannelTests.test_reversed_direction_fails` | A send-direction ciphertext cannot decrypt with the receive key. | PASS |
| `test_security.ChannelTests.test_aes256_key_lengths` | Non-32-byte AES keys are rejected. | PASS |
| `test_security.ChannelTests.test_hkdf_matches_independent_rfc5869_calculation` | Both derived halves equal independent HMAC extract/expand and differ from each other. | PASS |
| `test_security.ChannelTests.test_ecdh_and_fresh_keys` | Both peers derive identical keys; new ephemeral secrets produce fresh keys. | PASS |
| `test_security.ChannelTests.test_kdf_binds_identity_and_transcript` | Changing member identity or a transcript point changes derived keys. | PASS |
| `test_security.ChannelTests.test_frame_from_other_session_rejected` | Ciphertext from another session fails authentication. | PASS |
| `test_security.ChannelTests.test_reject_compressed_and_invalid_points` | Compressed, malformed and off-curve points are rejected. | PASS |
| `test_security.FramingRejectionTests.test_truncated_header` | Partial four-byte header is rejected on EOF. | PASS |
| `test_security.FramingRejectionTests.test_truncated_payload` | Partial payload is rejected on EOF. | PASS |
| `test_security.FramingRejectionTests.test_missing_payload` | Header followed by immediate EOF is rejected. | PASS |
| `test_security.FramingRejectionTests.test_zero_length` | Zero-length network frame is rejected. | PASS |
| `test_security.FramingRejectionTests.test_oversize` | Declared frame beyond the limit is rejected before allocation. | PASS |
| `test_security.FramingRejectionTests.test_bad_json_utf8_duplicates_and_nan` | Invalid UTF-8/JSON, duplicate fields and NaN are rejected. | PASS |
| `test_security.FramingRejectionTests.test_clean_disconnect` | EOF before a frame returns None. | PASS |
| `test_security.SetupTests.test_parameters` | p is 2048 bits, q/g follow specification, subgroup bounds are enforced. | PASS |
| `test_security.SetupTests.test_configurable_setup_and_independent_owners` | Six members plus server have distinct keys/certificates; repeat setup refuses overwrite. | PASS |
| `test_security.SetupTests.test_owner_setup_is_idempotent` | Repeated owner initialization preserves its existing key. | PASS |
| `test_security.SetupTests.test_invalid_threshold` | Threshold greater than member count is rejected. | PASS |
| `test_security.SetupTests.test_path_traversal_name` | Identity names cannot escape their own storage path. | PASS |

Additional executed smoke check: fresh owner-local setup for default n=5,t=3,
founder-issued server/M1?M5 certificates, independent secure M1 and M2 connections,
nonce-0 encrypted request and response. Logs are local, ignored by Git, at
`runtime/john-verification/logs/`. No private values or key bytes were printed.

Not tested as completed features: Schnorr login, signed requests/ledger, vault/A5,
voting/A7 or Wireshark evidence. Those are pending their assigned owners.
