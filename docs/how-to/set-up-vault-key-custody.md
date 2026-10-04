# How to set up Vault Transit key custody

Move the platform's encryption keys into HashiCorp Vault's Transit engine (decision D-3), so each tenant's keys never leave Vault.

## Prerequisites

- A Vault server with the Transit engine enabled, and a token that can create keys and call `encrypt`, `decrypt` and `hmac` on them. How the app logs in to Vault in production (AppRole or Kubernetes auth instead of a static token) is still open under D-3.
- Outside `local`/`test`, the Vault address must use `https://`. The app refuses to start otherwise.
- A **new** database, or one with no encrypted data yet. See [Switching an existing database](#switching-an-existing-database).

## Steps

1. Enable Transit, if it isn't already:

   ```bash
   vault secrets enable transit
   ```

2. Set the key-provider settings on every Python service (api, worker, outbox relay, migrate):

   ```bash
   IDP_KEY_PROVIDER=vault
   IDP_VAULT_ADDR=https://vault.example.internal:8200
   IDP_VAULT_TOKEN=<token>
   # IDP_VAULT_TRANSIT_MOUNT=transit   # only if Transit is mounted elsewhere
   ```

3. Create each tenant's keys. Run this after migrations and after adding any tenant, before the tenant takes requests:

   ```bash
   make vault-provision
   ```

   Expected output: `provisioned keys for 2 tenant(s)`. Running it again leaves existing keys unchanged.

4. Start or restart the services.

## Verification

List the keys. Each tenant has one KEK and one blind-index key:

```bash
vault list transit/keys
```

```
idp-bidx-a0000000-0000-4000-8000-000000000001
idp-kek-a0000000-0000-4000-8000-000000000001
...
```

Confirm a key can't be exported:

```bash
vault read -field=exportable transit/keys/idp-kek-<tenant_id>    # prints: false
```

Submit a test request. New values in the `enc_*` columns start with `v1.vault.`, where they used to start with `v1.local-1.`.

## Try it locally

The Compose stack includes an optional Vault in dev mode (in-memory, root token `dev-root-token`) under the `vault` profile. `make up` doesn't start it.

```bash
# 1. Start Vault and enable Transit (safe to repeat)
make vault-up

# 2. Point the Python services at it for this shell, then provision the dev tenants' keys
export IDP_KEY_PROVIDER=vault IDP_VAULT_ADDR=http://vault:8200 IDP_VAULT_TOKEN=dev-root-token
make vault-provision
# provisioned keys for 2 tenant(s)

# 3. Check the keys exist
docker compose -f infra/compose/docker-compose.yml --profile vault exec \
  -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=dev-root-token vault vault list transit/keys
```

To run the **whole stack** on Vault, keep those variables exported and start it on an empty database: `make clean && make up`. **This deletes all local data.** Data written under the local provider can't be read by the Vault provider (see [Switching an existing database](#switching-an-existing-database)). New `enc_*` values then start with `v1.vault.`.

Without the exports, the stack keeps using the local provider. Compose reads variables from your shell, or from `infra/compose/.env` if you create one (not from the repository root).

To stop Vault: `docker compose -f infra/compose/docker-compose.yml --profile vault stop vault`. It runs in memory, so its keys disappear when it stops, and anything encrypted with them can no longer be read.

## Rotating keys

- **KEK (`idp-kek-*`):** safe to rotate at any time with `vault write -f transit/keys/idp-kek-<tenant_id>/rotate`. Old wrapped data keys keep working, because each one records its key version.
- **Blind-index key (`idp-bidx-*`):** **never rotate it.** Every lookup hash is pinned to version 1. After a rotation no stored `bidx_*` value would match, so returning requesters and duplicate checks would stop finding anyone.

## Switching an existing database

There is no re-encryption tool. A provider only opens its own `key_id`: the Vault provider refuses `local-1` ciphertexts, and the local provider refuses `vault` ones. Both raise `DecryptionError("unknown key id")`. Blind indexes also come out differently under the two providers. So switch providers only on an empty database, such as a fresh environment or after `make clean` in dev.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| App won't start: `vault_addr and vault_token are required for the vault key provider` | One of the two is missing | Set both |
| App won't start: `vault_addr must use https outside local/test` | `http://` address in a non-dev environment | Use TLS |
| App won't start: `local key provider is only permitted in local/test` | `IDP_KEY_PROVIDER` left at `local` in production | Set `IDP_KEY_PROVIDER=vault` |
| `KeyServiceError: vault transit unreachable: ConnectError` | Vault is down or the address is wrong | Check the network path. This is an outage, not data corruption |
| `KeyServiceError: vault transit returned 403` | The token lacks permission on `transit/keys/idp-*`, `encrypt`, `decrypt` or `hmac` | Fix the Vault policy |
| `DecryptionError: unknown key id` | The data was written under the other provider | See [Switching an existing database](#switching-an-existing-database) |
| `make vault-provision` prints `IDP_KEY_PROVIDER is not 'vault'` | The variable isn't set in the shell running `make` (or in `infra/compose/.env`) | `export IDP_KEY_PROVIDER=vault IDP_VAULT_ADDR=http://vault:8200 IDP_VAULT_TOKEN=dev-root-token` |
| `KeyServiceError: vault transit unreachable` locally | The dev Vault isn't running | `make vault-up` |

## Related

- Reference: [Settings](../reference/privacy-protections.md#settings), [Key names in Vault](../reference/privacy-protections.md#key-names-in-vault), [Errors](../reference/privacy-protections.md#errors)
- Explanation: [The key hierarchy](../architecture/anonymisation-pseudonymisation.md#2-pseudonymisation-the-key-hierarchy)
- Decision D-3 in [open-decisions.md](../open-decisions.md)
