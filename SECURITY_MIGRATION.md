# Security migration to 0.3

Version 0.3 makes presentation session state single-owner and removes its
serialization surface so ephemeral secrets cannot be copied or persisted.
Code that cloned or serialized `SessionManagerInit`, `SessionManagerEngaged`,
or either device/reader `SessionManager` must instead transfer ownership and
persist only non-secret protocol data.

Verification-only builds no longer enable curve private-key codecs. Internal
P-256/P-384/P-521 certificate decoding uses explicit named-curve OIDs. The
established generic `X5Chain::end_entity_public_key` wrapper remains available
for consumers whose curve type implements `AssociatedOid`; minimal builds
should use the role-specific verifier APIs.
