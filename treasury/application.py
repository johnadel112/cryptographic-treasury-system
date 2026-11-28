"""Unified authentication, signed operations, vault openings and private voting."""
from datetime import datetime, timezone
import secrets
from .config import GROUP, P, Q, G, member_names
from .encoding import H, canonical_json, group_int, hex_int, sha256
from .ledger import StateStore
from .login import verify_interactive_login
from .requests import verify_request
from .opening import verify_decryption_share, combine_decryption_shares
from .vault import load_vault_public, trusted_verification_keys, open_vault
from .voting import verify_ballot, aggregate_ciphertexts, recover_yes_count


class TreasuryApplication:
    def __init__(self, root, identity, log, *, weaknesses=()):
        self.vault = load_vault_public(root)
        self.founder_public = identity.founder_public_key
        self.keys = trusted_verification_keys(self.vault)
        self.names = member_names(self.vault["n"])
        self.log = log
        self.weaknesses = frozenset(weaknesses)
        self.store = StateStore(root / "server" / "application.json", sha256(canonical_json(self.vault)).hex())
        log.info("founder commitments signature OK C0=%s t=%d n=%d", self.vault["vault_key"][:8], self.vault["t"], self.vault["n"])
        for weakness in self.weaknesses:
            log.warning("EDUCATIONAL WEAK MODE: %s", weakness)

    def handle(self, session, message):
        name = session.peer_name
        try:
            if name not in self.names:
                raise ValueError("unknown member")
            kind = message.get("type")
            if kind == "channel-probe":
                return {"type": "channel-probe-ack", "group": GROUP, "message": message.get("message"), "authenticated": session.authenticated}
            if kind == "info":
                state = self.store.snapshot()
                return {"ok": True, "vault": self.vault, "registered": name in state["members"],
                        "last_seq": state["last_seq"].get(name, 0), "X_M": state["members"].get(name)}
            if kind == "register":
                X = group_int(message["X_M"])
                with self.store.transaction() as state:
                    if name in state["members"]:
                        raise ValueError("already registered; replacement rejected")
                    state["members"][name] = format(X, "x")
                self.log.info("registration %s OK X=%s", name, format(X, "x")[:8])
                return {"ok": True}
            if isinstance(kind, str) and kind.startswith("login_"):
                return self._login(session, message)
            if not session.authenticated:
                raise ValueError("not authenticated")
            if kind == "ballot":
                return self._ballot(session, message)
            if kind is not None:
                raise ValueError("unknown message type")
            with self.store.transaction() as state:
                if not verify_request(session.peer_public_key, message, state["last_seq"].get(name, 0), name=name):
                    raise ValueError("request signature or sequence verification FAILED")
                result = self._operation(state, name, message["op"], message["body"])
                state["last_seq"][name] = message["seq"]
                state["ledger"].append({"time": datetime.now(timezone.utc).isoformat(), "member": name, **message})
            self.log.info("request %s seq=%d op=%s signature OK; accepted ledger entry", name, message["seq"], message["op"])
            return {"ok": True, "result": result}
        except (ValueError, KeyError, TypeError, OverflowError) as exc:
            if isinstance(message.get("type"), str) and message["type"].startswith("login_"):
                session.authenticated = False
                session.state.clear()
            self.log.warning("application rejection member=%s reason=%s", name, str(exc).replace("\n", " "))
            return {"ok": False, "error": str(exc)}

    def _login(self, session, message):
        name, kind = session.peer_name, message["type"]
        state = self.store.snapshot()
        if name not in state["members"]:
            raise ValueError("member not registered")
        X = group_int(state["members"][name])
        if kind in ("login_interactive_start", "login_noninteractive_nonce"):
            session.authenticated = False
            session.state.clear()
            if kind == "login_interactive_start":
                R = group_int(message["R"])
                e = secrets.randbits(4 if "short-challenge" in self.weaknesses else 128)
                session.state["pending"] = ("interactive", R, e)
                self.log.info("login %s challenge R=%s e=%s", name, format(R,"x")[:8], format(e,"x")[:8])
                return {"ok": True, "e": format(e, "x")}
            N = secrets.randbits(128)
            session.state["pending"] = ("noninteractive", N)
            self.log.info("login %s fresh nonce N=%s", name, format(N,"x")[:8])
            return {"ok": True, "N": format(N, "x")}
        pending = session.state.pop("pending", None)  # consume even on a bad proof
        session.authenticated = False
        if not pending:
            raise ValueError("no pending challenge/nonce; replay rejected")
        if kind == "login_interactive_finish" and pending[0] == "interactive":
            _, R, e = pending
        elif kind == "login_noninteractive" and pending[0] == "noninteractive":
            R = group_int(message["R"])
            e = H("login", name, X, R, pending[1], q=Q)
        else:
            raise ValueError("login stage mismatch")
        z = hex_int(message["z"], limit=Q)
        ok = verify_interactive_login(R, z, e, X)
        self.log.info("login %s R=%s e=%s z=%s g^z=R*X^e: %s", name,
                      format(R,"x")[:8], format(e,"x")[:8], format(z,"x")[:8], "OK" if ok else "FAILED")
        if not ok:
            raise ValueError("invalid Schnorr proof")
        session.authenticated = True
        return {"ok": True, "last_seq": state["last_seq"].get(name, 0)}

    @staticmethod
    def _summary(operation):
        result = {k: v for k, v in operation.items() if k not in ("ballots", "contributions")}
        result["ballot_count"] = len(operation.get("ballots", {}))
        result["contribution_count"] = len(operation.get("contributions", {}))
        return result

    def _operation(self, state, name, op, body):
        if op == "overview":
            # Explicit public projection: never ship proofs, ballots or recovered bytes.
            fields = ("id", "kind", "state", "vote_number", "amount", "reason", "total", "approved")
            operations = []
            for operation in list(state["operations"].values())[-100:]:
                row = {key: operation[key] for key in fields if key in operation}
                row.update(ballot_count=len(operation.get("ballots", {})),
                           contribution_count=len(operation.get("contributions", {})),
                           contributors=sorted(operation.get("contributions", {})),
                           has_ballot=name in operation.get("ballots", {}),
                           has_contribution=name in operation.get("contributions", {}))
                operations.append(row)
            ledger = [{key: entry[key] for key in ("time", "member", "seq", "op")}
                      for entry in state["ledger"][-100:]]
            return {"group": GROUP, "n": self.vault["n"], "t": self.vault["t"],
                    "operations": operations, "ledger": ledger,
                    "operation_total": len(state["operations"]), "ledger_total": len(state["ledger"])}
        if op == "ping":
            return {"message": "pong"}
        if op == "share-complaint":
            self.log.warning("signed share complaint from %s: refusing participation", name)
            return {"recorded": True}
        if op == "open-vault":
            operation_id = "vault-" + secrets.token_hex(16)
            operation = {"id": operation_id, "kind": "vault", "state": "collecting",
                         "c1": self.vault["elgamal"]["c1"], "c2": self.vault["elgamal"]["c2"], "contributions": {}}
            state["operations"][operation_id] = operation
            return self._summary(operation)
        if op == "spend":
            if set(body) != {"amount", "reason"} or type(body["amount"]) is not int or not 0 < body["amount"] < (1 << 63) or not isinstance(body["reason"], str) or not 0 < len(body["reason"]) <= 500:
                raise ValueError("spend requires positive integer amount and bounded reason")
            vote = state["next_vote"]
            state["next_vote"] += 1
            operation = {"id": f"vote-{vote}", "vote_number": vote, "kind": "vote", "state": "voting",
                         "amount": body["amount"], "reason": body["reason"], "ballots": {}, "contributions": {}}
            state["operations"][operation["id"]] = operation
            return self._summary(operation)
        if op == "ledger":
            return {"entries": state["ledger"][:]}
        if op not in ("status", "contribute"):
            raise ValueError("unsupported operation")
        operation_id = body.get("operation")
        if not isinstance(operation_id, str) or operation_id not in state["operations"]:
            raise ValueError("unknown operation")
        operation = state["operations"][operation_id]
        if op == "status":
            return self._summary(operation)
        if operation["state"] != "collecting":
            raise ValueError("operation not accepting contributions")
        if name in operation["contributions"]:
            raise ValueError("duplicate member contribution")
        contribution = body["proof"]
        digest = sha256(canonical_json([GROUP, "contribution", contribution])).hex()
        if digest in state["used_proofs"]:
            raise ValueError("contribution replay across operations")
        index = int(name[1:])
        c1 = group_int(operation["c1"])
        weak = "no-proof" if "no-proof" in self.weaknesses else None
        if not verify_decryption_share(contribution, c1, verification_key=self.keys[index], member_index=index, weak=weak):
            raise ValueError("decryption proof verification FAILED")
        operation["contributions"][name] = contribution
        state["used_proofs"].append(digest)
        self.log.info("operation=%s member=%s d=%s proof=%s", operation_id, name,
                      contribution["d_i"][:8], "SKIPPED (weak)" if weak else "OK")
        if len(operation["contributions"]) >= self.vault["t"]:
            contributions = list(operation["contributions"].values())
            if operation["kind"] == "vault":
                plaintext = open_vault(self.vault, contributions, founder_public_key=self.founder_public, weak=weak)
                operation["state"] = "opened" if plaintext is not None else "failed"
                if plaintext is not None:
                    operation["content_hex"] = plaintext.hex()  # delivered only to logged-in members
                self.log.info("operation=%s vault recovery %s", operation_id, operation["state"])
            else:
                combined = combine_decryption_shares(contributions, c1, self.vault["t"], verification_keys=self.keys, weak=weak)
                element = group_int(operation["c2"]) * pow(combined, -1, P) % P
                try:
                    total = recover_yes_count(element, len(operation["ballots"]))
                except ValueError:
                    operation["state"] = "failed"
                    self.log.warning("operation=%s tally outside permitted range", operation_id)
                else:
                    operation.update(state="finalized", total=total, approved=total >= 3)
                    self.log.info("operation=%s aggregate total=%d approved=%s (rule >=3)", operation_id, total, total >= 3)
        return self._summary(operation)

    def _ballot(self, session, message):
        name = session.peer_name
        if not verify_ballot(session.peer_public_key, name, message, unsigned="unsigned-ballots" in self.weaknesses):
            raise ValueError("ballot signature/encoding verification FAILED")
        with self.store.transaction() as state:
            vote_id = f"vote-{message['vote_number']}"
            if vote_id not in state["operations"]:
                raise ValueError("unknown vote")
            vote = state["operations"][vote_id]
            if vote["state"] != "voting":
                raise ValueError("vote finalized or ballot collection closed")
            if name in vote["ballots"]:
                raise ValueError("duplicate ballot")
            vote["ballots"][name] = message
            if len(vote["ballots"]) == self.vault["n"]:
                c1, c2 = aggregate_ciphertexts(vote["ballots"].values())
                # Validate aggregates before offering a decryption operation.
                group_int(format(c1, "x")); group_int(format(c2, "x"))
                vote.update(state="collecting", c1=format(c1, "x"), c2=format(c2, "x"))
            result = self._summary(vote)
        self.log.info("ballot accepted member=%s operation=%s signature=%s; encrypted only", name, vote_id,
                      "SKIPPED (weak)" if "unsigned-ballots" in self.weaknesses else "OK")
        return {"ok": True, "result": result}
