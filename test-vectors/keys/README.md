# test-vectors/keys/ — test-only signing keys

**WARNING.** Every key in this directory is committed in plaintext
to the public mzprov repository on purpose. They exist so that
the cross-implementation test vectors are reproducible.

These keys MUST NOT be used to sign real data. They MUST NOT be
added to any production trusted-keys registry. They MUST NOT
appear in any sidecar that ships outside the `test-vectors/`
tree.

Conforming implementations SHOULD reject these key ids when they
appear in production verification contexts. The known test-only
key ids will be enumerated in `spec/key-id-derivation.md` once
that document lands.
