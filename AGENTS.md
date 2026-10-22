# Agent guidance

- Make small changes with tests and explicit invariants.
- Never claim the native receipt is a zero-knowledge proof.
- Keep Bitcoin consensus verification delegated to Bitcoin Core or an explicitly trusted independent verifier.
- Do not introduce unsafe code or direct network calls in the deterministic transition core.
- Pin protocol rules to activation heights and preserve legacy behavior in golden fixtures.
- Treat inputs, scripts, prevouts, and untrusted proof artifacts as adversarial.
