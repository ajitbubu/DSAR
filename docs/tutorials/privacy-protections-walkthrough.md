# See privacy protections in action

In about 15 minutes you'll take one erasure request through the local stack and watch the platform protect personal data three ways:

- It pseudonymises the requester inside its own database.
- It anonymises a support ticket in the (mock) CRM.
- It shreds the requester's identifiers once the case is closed.

By the end you'll know what each protection looks like on screen and in the database.

## What you'll need

- The prerequisites from the [README](../../README.md#prerequisites): Docker, uv, pnpm. Run `uv sync --all-packages && pnpm install` once.
- About 15 minutes. Nothing here touches real data: the tenants, people and source systems are all synthetic.

## Step 1: Start the stack

```bash
make up
```

This builds and starts every service and waits until they're healthy. It also migrates the database and seeds two tenants on policy pack DPDP 1.2.0, the version that anonymises support history. When it returns, check:

```bash
docker compose -f infra/compose/docker-compose.yml exec -T postgres psql -U idp_migrator -d idprivacy \
  -c "SELECT t.slug, p.pack_version FROM tenant_policy_pack p JOIN tenant t ON t.id = p.tenant_id;"
```

Both tenants show `1.2.0`.

## Step 2: Submit an erasure request as the data subject

Open http://localhost:3000/r/acme and fill in:

| Field | Value |
|---|---|
| Full name | Priya Sharma |
| How should we contact you? | **Mobile (SMS)** |
| Mobile number | `+919876543210` |
| I agree… | ticked |

Click **Continue**. The verify screen shows a **Reference** (for example `DPR-2026-MEM92H`) and, because the stack runs in test mode, the one-time code. Enter the code and click **Verify**. The page says **In progress**.

Keep this tab open, and note the reference. The steps below call it `REF`:

```bash
REF=DPR-2026-MEM92H   # yours will differ
```

Why phone, not email? The mock CRM's support ticket is linked to Priya only by phone number. The platform searches source systems only with identifiers it has verified, and only the contact you verify by code counts.

## Step 3: See the requester pseudonymised

Get the dev staff password from the Keycloak fixture:

```bash
python3 -c "import json; print(json.load(open('infra/compose/keycloak/idprivacy-realm.json'))['users'][0]['credentials'][0]['value'])"
```

In a second window, open http://localhost:3000/ops and sign in as `analyst@acme.example.test`. Click your reference. The **Identifiers** panel shows the phone number as `+91•••••210`. Staff never see the full value.

Now look at what's actually stored:

```bash
docker compose -f infra/compose/docker-compose.yml exec -T postgres psql -U idp_migrator -d idprivacy -c "
  SELECT type, assurance, left(bidx, 16) AS bidx, left(enc_value, 28) AS enc_value
  FROM request_identifier WHERE request_id = (SELECT id FROM privacy_request WHERE display_id = '$REF');"
```

```
 type  | assurance |       bidx       |          enc_value
-------+-----------+------------------+------------------------------
 PHONE | VERIFIED  | 489d49cc3d87e135 | v1.local-1.VnQBbHgJeWE22wmlY
```

`enc_value` is AES-256-GCM ciphertext. `local-1` names the dev key provider, and in production it reads `vault`. `bidx` is a keyed hash, so the platform can find "this phone number" without storing it. Search the whole database for the plain number:

```bash
docker compose -f infra/compose/docker-compose.yml exec -T postgres pg_dump -U idp_migrator -d idprivacy --data-only 2>/dev/null \
  | grep -c -E "9876543210|Priya"
```

The result is `0`.

## Step 4: Review: one record will be anonymised, not deleted

Open the case's **Discovery** tab. The worker found 3 records across 2 sources. Then open **Retention** and click **Start review**:

| Record | Decision | Basis |
|---|---|---|
| `crm:contact:c-1001` | Delete | Rule default-erase |
| `crm:ticket:t-7001` | **Anonymise** | Rule support-history-anonymise |
| `docs:file:d-3002` | Delete | Rule default-erase |

The ticket's `support` category matched the 1.2.0 rule. Click **Submit for approval**, then **Sign out**.

## Step 5: Approve as a second person

Sign in at http://localhost:3000/ops as `approver@acme.example.test` (same password). Open the case, go to **Approval**, and click **Approve**. One person can't both review and approve.

Within a few seconds the worker sends the actions to the connectors, verifies them and closes the case.

## Step 6: Check the anonymisation was proven

Open the case's **Verification** tab:

| Record | Expected | Source says | Rescan | Result |
|---|---|---|---|---|
| `crm:ticket:t-7001` | anonymized | anonymized | not found | pass |

The connector says it anonymised the ticket. Separately, the platform searched again with Priya's phone number and no longer found it. Both have to hold for a pass.

Switch to the requester tab and reload. It says **Your request is closed** and "2 records were deleted. 1 record was anonymised."

## Step 7: Shred the case after closure

A closed case keeps Priya's encrypted identifiers for 30 days, in case she follows up. After that, a daily job shreds them. To skip the wait on this dev case, move its closing date back and run the job:

```bash
docker compose -f infra/compose/docker-compose.yml exec -T postgres psql -U idp_migrator -d idprivacy \
  -c "UPDATE privacy_request SET closed_at = closed_at - interval '31 days' WHERE display_id = '$REF';"
make minimise-closed
```

```
minimised 1 case(s); 0 held back by a legal hold
```

Reload the case overview in the console. The Identifiers panel now says "The requester's identifiers were deleted on …". Run the Step 3 query again: it returns no rows. The case's decisions, verification results and audit chain are still there, so the evidence survives without naming anyone.

## What you built

You took one request end to end and saw each layer at work:

- **Pseudonymisation:** encrypted columns and keyed-hash lookups, with only masked values on screen.
- **Anonymisation at source:** a policy rule chose it, a second person approved it, and a connector carried it out, with a rescan to prove it.
- **Post-closure minimisation:** a scheduled job that crypto-shreds identifiers after the grace period.

Next:

- [Privacy protections reference](../reference/privacy-protections.md): every setting, column and command.
- [How to run post-closure minimisation](../how-to/run-post-closure-minimisation.md) in a real environment.
- [How to set up Vault Transit key custody](../how-to/set-up-vault-key-custody.md) for production keys.
- [How to anonymise a record category instead of deleting it](../how-to/anonymise-instead-of-delete.md).
- [Anonymisation and Pseudonymisation](../architecture/anonymisation-pseudonymisation.md): why it's designed this way.

To reset everything: `make clean && make up`.
