# How to run post-closure minimisation

Shred the requester's identifiers from cases that closed more than their grace period ago (decision D-12), then confirm what was removed.

## Prerequisites

- The stack is running (`make up`), and migrations are at `0012_minimisation` or later. The `migrate` service applies them on start.
- Each case's pinned policy pack sets the grace period through `post_closure_retention_days` (DPDP 1.2.0: 30 days). Cases pinned to older packs use the default of 30. See the [reference](../reference/privacy-protections.md#policy-pack-field).

## Steps

1. Run the job.

   ```bash
   make minimise-closed
   ```

   Expected output:

   ```
   minimised 1 case(s); 0 held back by a legal hold
   ```

   Running it again is safe. A second run straight afterwards prints `minimised 0 case(s)`.

2. Schedule it daily. Production scheduling is still open (D-12). Until then, any scheduler that can run this one command works. For example, a crontab entry on the host that runs the stack:

   ```cron
   15 2 * * *  cd /srv/idprivacy && make minimise-closed >> /var/log/idprivacy/minimise.log 2>&1
   ```

3. To keep a case's data past its grace period, place a legal hold before the job runs. Use the case's **Retention** tab in the console (scope "All requests from this person" or the case itself). A hold on a connector or a record type the case touched also blocks it. Held cases are counted in the `held back` number and are minimised on the first run after the hold is released.

## Verification

Check one case in the database. Replace the display id with yours:

```bash
docker compose -f infra/compose/docker-compose.yml exec -T postgres \
  psql -U idp_migrator -d idprivacy -c "
  SELECT display_id, minimised_at,
         enc_full_name IS NULL AS name_shredded,
         (SELECT count(*) FROM request_identifier i WHERE i.request_id = r.id) AS identifiers_left
  FROM privacy_request r WHERE display_id = 'DPR-2026-MEM92H';"
```

A minimised case shows a `minimised_at` timestamp, `name_shredded = t` and `identifiers_left = 0`.

Each minimised case also writes one audit event:

```bash
docker compose -f infra/compose/docker-compose.yml exec -T postgres \
  psql -U idp_migrator -d idprivacy -c \
  "SELECT details FROM audit_event WHERE action = 'request.minimised' ORDER BY seq DESC LIMIT 1;"
```

```
{"blobs_deleted": 0, "principal_shredded": false, "resolved_ids_deleted": 1}
```

In the console, the case overview's Identifiers panel says "The requester's identifiers were deleted on …".

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `minimised 0 case(s)` but you expected one | The case closed less than `post_closure_retention_days` ago, or it was already minimised | Check `closed_at` and `minimised_at` on `privacy_request`, and the pinned pack's `post_closure_retention_days` |
| A case is counted in `held back` every day | An unreleased legal hold covers the case, the person, a connector or a record type it touched | Release the hold if it's no longer needed. The next run minimises the case |
| `principal_shredded: false` | The same person has another request that isn't minimised yet. Their shared identifiers stay until the last one is minimised | Expected. Nothing to do |
| `KeyError: 'IDP_DATABASE_URL_MIGRATOR'` | You ran the script outside the `migrate` container | Use `make minimise-closed`, which runs inside it |
| A requester can't sign back in to an old case | The case is minimised, so its contact details are gone. Sign-in answers as if no case matches | Expected (D-12) |

## Try it on a dev case

To see the job act on a case today without waiting 30 days, move a **dev** case's closing date back. Never do this on real data, because it destroys identifiers early.

```bash
docker compose -f infra/compose/docker-compose.yml exec -T postgres \
  psql -U idp_migrator -d idprivacy -c \
  "UPDATE privacy_request SET closed_at = closed_at - interval '31 days' WHERE display_id = 'DPR-2026-MEM92H';"
make minimise-closed
```

## Related

- Reference: [What minimisation changes](../reference/privacy-protections.md#what-minimisation-changes)
- Explanation: [Post-closure minimisation (D-12)](../architecture/anonymisation-pseudonymisation.md#4-post-closure-minimisation-d-12)
- Tutorial: [See privacy protections in action](../tutorials/privacy-protections-walkthrough.md)
