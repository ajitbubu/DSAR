# How to anonymise a record category instead of deleting it

Change an erasure policy so that records in a data category are anonymised in the source system rather than deleted. This is how DPDP 1.2.0 keeps support history (`support`) without identifying anyone.

## Prerequisites

- Every connector that holds records of that category supports the `ANONYMIZE` action. Check its descriptor's `supported_actions`. The platform never sends an unsupported action, but it only notices at fulfilment, after approval (see Troubleshooting).
- Legal sign-off for the rule. The DPDP packs are engineering drafts until legal review (D-9, D-14).

## Steps

1. Copy the latest pack to a new version. Published packs are immutable, so never edit one in place.

   ```bash
   mkdir -p packages/policy-packs/dpdp/1.3.0
   cp packages/policy-packs/dpdp/1.2.0/pack.yaml packages/policy-packs/dpdp/1.3.0/pack.yaml
   ```

2. In the new file, set `version: 1.3.0`, update the header comment's change list, and add a rule under `retention_rules`. Rules are checked top to bottom and the first match wins. Put the new rule **after** `legal-hold`, `unconfirmed-link` and any `MANUAL_REVIEW` rules, and **before** `default-erase`:

   ```yaml
   - id: feedback-anonymise
     when: { data_categories_any: [feedback] }
     decision: ANONYMIZE
   ```

   You can match on `record_types_any` instead (for example `[crm.survey]`). Rule ids must match `^[a-z][a-z0-9-]{1,63}$`.

3. Validate the pack and pin its hash in `manifest.json`:

   ```bash
   make policy-pin PACK=packages/policy-packs/dpdp/1.3.0/pack.yaml
   ```

   ```
   pinned DPDP@1.3.0 <sha256>
   ```

   A validation error here (an unknown field, or `RETAIN requires an exception_code`) means the pack wasn't pinned. Fix it and rerun.

4. Point the dev tenants at the new version in `apps/api/src/idprivacy/scripts/seed_dev.py`:

   ```python
   DEV_PACKS = [("DPDP", "1.3.0")]
   ```

   `tests/test_seed_dev.py` fails until you do, because it requires the seed to enable the newest pinned pack.

5. Publish and reseed:

   ```bash
   make up
   ```

   The `migrate` service runs `policy_packs publish`, then `seed_dev`.

Existing cases stay pinned to the version they were decided under. Only new cases use 1.3.0.

Moving a production tenant to a new version has no command or API yet. Today only `seed_dev.py` writes the `tenant_policy_pack` rows.

## Verification

1. Confirm the tenants run the new version:

   ```bash
   docker compose -f infra/compose/docker-compose.yml exec -T postgres psql -U idp_migrator -d idprivacy \
     -c "SELECT t.slug, p.pack_version FROM tenant_policy_pack p JOIN tenant t ON t.id = p.tenant_id;"
   ```

2. Submit an erasure request that matches a record in the category. Its **Retention** tab shows **Anonymise** with "Rule feedback-anonymise". After approval, the **Verification** tab shows `anonymized` / `anonymized` / `not found` / `pass`.

3. Run the API tests: `make test-api`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The record still shows **Delete** | An earlier rule matched first, or the case is pinned to an older pack | Move the rule up, or test with a new case |
| Fulfilment task `FAILED_FINAL` with code `action_unsupported` | The connector doesn't support `ANONYMIZE` (the mock document store supports only `DELETE` and `RESTRICT`) | Pick a different decision for that record type, or add the capability to the connector |
| Verification fails although the connector reports `anonymized` | The rescan still finds the record, so the connector left an identifier on it | Fix the connector so that it removes every field the identifiers match on |
| `make up` fails in `migrate` with a hash mismatch | The pack was edited after pinning | Run `make policy-pin` again on the new version. Never re-pin a published version |
| `test_seed_dev.py` fails | `DEV_PACKS` doesn't name the newest pinned version | Update `DEV_PACKS` |

## Related

- Reference: [Policy-pack field and retention rules](../reference/privacy-protections.md#policy-pack-field), [Anonymisation in source systems](../reference/privacy-protections.md#anonymisation-in-source-systems)
- Explanation: [Anonymisation: from decision to verification](../architecture/anonymisation-pseudonymisation.md#3-anonymisation-from-decision-to-verification)
- Tutorial: [See privacy protections in action](../tutorials/privacy-protections-walkthrough.md)
