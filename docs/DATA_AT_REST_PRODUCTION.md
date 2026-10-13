# Production data-at-rest profile

`CCOS_ENTERPRISE_DATA_AT_REST_PROFILE=production` makes the stdio front door
fail closed unless every durable data class used by that process is covered by
an explicit at-rest policy. Set `CCOS_ENTERPRISE_DATA_AT_REST_POLICY` to a
bounded, regular, non-symlink JSON file such as
[`data-at-rest-policy.example.json`](data-at-rest-policy.example.json).
Set `CCOS_ENTERPRISE_BACKUP_ROOTS_JSON` to the ordered JSON array of local
backup roots used by the deployment, for example
`["/srv/ccos-backup/acme"]`; it must match `backup_roots` exactly.
Set `CCOS_ENTERPRISE_PURGE_FLOOR_RECEIPT` to an operator-retained receipt such
as [`purge-floor-receipt.example.json`](purge-floor-receipt.example.json).
Set `CCOS_ENTERPRISE_BACKUP_RECONCILIATION_RECEIPTS_JSON` to the ordered JSON
array of receipt paths, one for each backup root, using
[`backup-reconciliation-receipt.example.json`](backup-reconciliation-receipt.example.json)
as the schema example.

The profile inventories and checks these distinct durability boundaries:

| Data class | Runtime path | Required protection |
| --- | --- | --- |
| Governance, effect, execution, correlation, skill and Core journals | `CCOS_ENTERPRISE_STATE_DIR` | operator-managed encrypted volume |
| Governed provider generations, selector, purge floor and rotation intent | `CCOS_ENTERPRISE_GOVERNED_MEMORY_ROOT` | application envelope plus configured `CCOS_ENTERPRISE_ENVELOPE_CONFIG` |
| Knowledge/evidence journal | `CCOS_ENTERPRISE_EVIDENCE_KNOWLEDGE_ROOT`, when enabled | operator-managed encrypted volume |
| Exact source blobs | `CCOS_ENTERPRISE_SOURCE_BLOBS_ROOT`, when enabled | operator-managed encrypted volume |
| Independent local backup generations | every `backup_roots` entry | operator-managed encrypted volume |

All roots must already exist as absolute directories with no symlink in any
path component. Their canonical paths must match the process configuration,
and no two lifecycle classes may alias the same directory. Evidence roots and
declarations are all-or-nothing. At least one independently protected backup
root is mandatory; the runtime backup-root array and policy inventory must
have the same length and order.

The provider envelope is enforced by the application. The other protection
class is an operator assertion about the mounted storage boundary; CCOS cannot
prove that a disk, filesystem or remote backup service actually encrypts its
bytes. Deployment qualification must therefore retain storage/KMS evidence
outside the repository and bind it to `key_policy_ref` and each opaque
`key_scope`. Do not put keys, tokens or credentials in the policy.

Restore policy is deliberately evidence-based rather than a static assertion:

- the purge-floor receipt is stored outside every declared lifecycle root and
  binds the tenant, canonical provider root and provider generation to the
  SHA-256 of the live `provider-purge-floor.json`; replacing the provider with
  an older image therefore fails startup;
- each external reconciliation receipt binds one canonical backup root, its
  key scope and current key-policy reference, the same provider generation,
  and the SHA-256 of that backup's `ccos-backup-manifest.json`;
- receipts and manifests are bounded regular files with no symlink component.

The operator must update and durably retain these receipts after a successful
purge or backup reconciliation, before restoring a provider or retiring an old
key version. CCOS verifies exact byte identity and binding at startup; the
operator remains responsible for protecting the external receipt store from
rollback.

This gate prevents a production-labelled process from silently using the
development plaintext profile. It does not establish FIPS certification,
forensic erasure, production Vault/HSM/IAM qualification, or encryption of
copies outside the declared roots.

