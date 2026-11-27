# Technical explanation guide

Every student should be able to trace a message from owner CLI through TCP framing, session verification, application transaction and response. The final implementation keeps the team's mathematical work while removing the competing src protocol stack.

| Concept | Reasoning and limits | Code to explain |
|---|---|---|
| ECDH / forward secrecy | Fresh P-256 ephemeral keys derive a shared point secret each connection. Later compromise of a long-term signing key does not reveal old ephemeral DH secrets; runtime compromise and retained secrets remain risks. | channel.member_handshake, server_handshake, generate_p256_keypair |
| ECDSA / certificates | Founder signature binds name, GROUP, public key and expiry. Role-labelled handshake signatures bind both ephemeral points to identity. A valid channel is not Schnorr login. | certificates.check_certificate; channel._verify |
| HKDF | Domain-separated directional keys avoid key reuse between send/receive; salt/info bind the session and GROUP. HKDF is extraction/expansion, not password hashing. | channel.derive_directional_keys; vault.derive_file_key |
| AES-GCM | Provides confidentiality and authenticated integrity. Directional counters produce nonrepeating nonces per fresh key and reject reordered/replayed frames. Reuse of a key/nonce pair would break security. | channel.SecureChannel; framing.recv_frame |
| Schnorr | Prover chooses fresh k, sends R=g^k, responds z=k+ex mod q; verifier checks g^z=R X^e. Reusing k leaks x. Interactive e has 128 random bits; NI e is H(login,name,X,R,N), with fresh single-use server nonce N. | login.make_commitment, make_interactive_response, verify_interactive_login, make_noninteractive_response; application.handle |
| Signed operations | Outer signature binds identity/GROUP/sequence/op/body. Persistent sequence rejects replay; transaction validation prevents rejected operations entering the accepted ledger. | requests.request_transcript, verify_request; ledger.StateStore.transaction |
| Shamir | Degree t-1 polynomial f over Zq shares f(i); fewer than t scalar shares do not determine f(0). Setup must use cryptographic randomness and fresh coefficients. | sharing.make_shares, evaluate_polynomial |
| Feldman | Commitments Cj=g^aj permit verifying g^si=product Cj^(i^j) without publishing si. They are computationally hiding for high-entropy coefficients, not perfectly hiding. Founder signature prevents replacing the commitment set. | sharing.feldman_commitments, verify_share, verification_key; vault.check_vault_public |
| Lagrange | Coefficients at zero combine di=c1^si in the exponent into c1^s. Production opening never interpolates the scalar s. Shamir reconstruction appears only in arithmetic tests. | sharing.lagrange_coefficient; opening.combine_decryption_shares |
| Chaum-Pedersen | Proves log_g(hi)=log_c1(di). Check g^z=T1 hi^e AND c1^z=T2 di^e, e=H(dec,i,c1,hi,di,T1,T2). Trusted hi derives from signed commitments. Signed operation binding and replay tracking are additional protections. | opening.make_decryption_share, verify_decryption_share; application._operation |
| File vault | ElGamal encapsulates random subgroup element m; HKDF derives file key; AES-GCM encrypts file. The founder discards s, coefficients and ephemeral r without persisting them. Python cannot guarantee physical memory zeroization. | vault.vault_setup, open_vault |
| Homomorphic voting | Ballot (g^r, h^r*g^v) with fresh r, v in {0,1}. Component-wise multiplication encrypts sum(v); decrypt only the aggregate using the same vault key. Search g^j for j=0..n; >=3 yes approves independent of t. | voting.encrypt_vote, aggregate_ciphertexts, recover_yes_count; application._ballot |
| Ballot limitations | Signature authenticates ciphertext, not bit validity. A malicious member can encode another exponent, possibly yielding an apparently valid tally. A suitable OR/bit zero-knowledge proof would prove encryption of 0 or 1. No such proof is required/implemented here. | voting.verify_ballot; tests/test_private_voting.py |

## Trace these failures without memorizing output

A1 removes ECDSA authentication of ephemeral DH and permits two Mallory sessions; signed application requests still bind their contents. A5 removes proof equations, causing wrong reconstructed encapsulation and GCM tag failure; secure mode rejects M3 before threshold counting. A7 removes ballot signature verification and permits c2*g to add one; enabled signatures detect modification. A3 shortens challenge entropy so guessing can work; the attack owns the signing identity but does not read its independent Schnorr secret.

## Operational boundaries

Only owner processes load their identity/login/share files; founder alone distributes shares at setup. This is not OS-level isolation against a hostile same-account process. Thread-level atomic state prevents concurrent duplicate acceptance; run one server per runtime root. Local-only weakness flags are intentional educational configurations, never remotely settable. Founder trust, threshold collusion, denial of service, absent voters, stored recovered plaintext, and Python zeroization are documented limits. The code is a university protocol implementation, not a production wallet.

See tests/test_security.py and test_processes.py for channel checks, test_authentication.py for state/authentication, test_vault.py for trust/proofs/owner isolation, test_private_voting.py for lifecycle/counts, and test_end_to_end.py for real CLI processes. Explain why a passing helper test alone would not prove that the application actually uses the helper.
