# Signing Keys

Development and production signing keys must not be committed. Production deployments should load signing material from a KMS, secret manager, or read-only secret mount and publish only public keys through JWKS.
