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

The Compose stack has no Vault service, and it doesn't pass `IDP_KEY_PROVIDER` or `IDP_VAULT_*` into its containers. Setting them in `.env` or your shell does nothing: `make vault-provision` then exits with `IDP_KEY_PROVIDER is not 'vault'; nothing to provision`. Instead, run a throwaway Vault on the Compose network and pass the settings with `docker compose run -e`:

```bash
# 1. Vault in dev mode on the stack's network (in-memory, root token "dev-root-token")
docker run -d --name idp-vault --network idprivacy_default \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-root-token hashicorp/vault:1.17
docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=dev-root-token \
  idp-vault vault secrets enable transit

# 2. Provision the dev tenants' keys
docker compose -f infra/compose/docker-compose.yml run --rm --no-deps \
  -e IDP_KEY_PROVIDER=vault -e IDP_VAULT_ADDR=http://idp-vault:8200 -e IDP_VAULT_TOKEN=dev-root-token \
  migrate python -m idprivacy.scripts.vault_provision
# provisioned keys for 2 tenant(s)

# 3. Round trip through the real cipher
docker compose -f infra/compose/docker-compose.yml run --rm --no-deps \
  -e IDP_KEY_PROVIDER=vault -e IDP_VAULT_ADDR=http://idp-vault:8200 -e IDP_VAULT_TOKEN=dev-root-token \
  migrate python -c "
from uuid import UUID
from idprivacy.config import get_settings
from idprivacy.platform.crypto import FieldCipher
from idprivacy.runtime import build_keys
t = UUID('a0000000-0000-4000-8000-000000000001')
c = FieldCipher(build_keys(get_settings()))
token = c.encrypt(t, 'demo.check', 'priya.sharma@example.in')
print(token.split('.')[:2], c.decrypt(t, 'demo.check', token) == 'priya.sharma@example.in')"
# ['v1', 'vault'] True

# 4. Clean up
docker rm -f idp-vault
```

This checks provisioning and the cipher only. Running the whole stack on Vault needs the Compose file to pass the four `IDP_KEY_PROVIDER`/`IDP_VAULT_*` variables to its Python services, which it doesn't do today.

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
| `make vault-provision` prints `IDP_KEY_PROVIDER is not 'vault'` | The setting didn't reach the container (the Compose gap above) | Pass it with `docker compose run -e`, or set it in the service's real environment |

## Related

- Reference: [Settings](../reference/privacy-protections.md#settings), [Key names in Vault](../reference/privacy-protections.md#key-names-in-vault), [Errors](../reference/privacy-protections.md#errors)
- Explanation: [The key hierarchy](../architecture/anonymisation-pseudonymisation.md#2-pseudonymisation-the-key-hierarchy)
- Decision D-3 in [open-decisions.md](../open-decisions.md)
