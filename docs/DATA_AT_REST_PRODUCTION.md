# Production data-at-rest profile

`CCOS_ENTERPRISE_DATA_AT_REST_PROFILE=production` makes the stdio front door
fail closed unless every durable data class used by that process is covered by
an explicit at-rest policy. Set `CCOS_ENTERPRISE_DATA_AT_REST_POLICY` to a
bounded, regular, non-symlink JSON file such as
[`data-at-rest-policy.example.json`](data-at-rest-policy.example.json).
Set `CCOS_ENTERPRISE_BACKUP_ROOTS_JSON` to the ordered JSON array of local
backup roots used by the deployment, for example
`["/srv/ccos-backup/acme"]`; it must match `backup_roots` exactly.

The profile inventories and checks these distinct durability boundaries:

| Data class | Runtime path | Required protection |
| --- | --- | --- |
| Governance, effect, execution, correlation, skill and Core journals | `CCOS_ENTERPRISE_STATE_DIR` | operator-managed encrypted volume |
| Governed provider generations, selector, purge floor and rotation intent | `CCOS_ENTERPRISE_GOVERNED_MEMORY_ROOT` | application envelope plus configured `CCOS_ENTERPRISE_ENVELOPE_CONFIG` |
| Knowledge/evidence journal | `CCOS_ENTERPRISE_EVIDENCE_KNOWLEDGE_ROOT`, when enabled | operator-managed encrypted volume |
| Exact source blobs | `CCOS_ENTERPRISE_SOURCE_BLOBS_ROOT`, when enabled | operator-managed encrypted volume |
| Independent local backup generations | every `backup_roots` entry | operator-managed encrypted volume |

All roots must already exist as absolute, non-symlink directories. Their
canonical paths must match the process configuration, and no two lifecycle
classes may alias the same directory. Evidence roots and declarations are
all-or-nothing. At least one independently protected backup root is mandatory;
the runtime backup-root array and policy inventory must have the same length
and order.

The provider envelope is enforced by the application. The other protection
class is an operator assertion about the mounted storage boundary; CCOS cannot
prove that a disk, filesystem or remote backup service actually encrypts its
bytes. Deployment qualification must therefore retain storage/KMS evidence
outside the repository and bind it to `key_policy_ref` and each opaque
`key_scope`. Do not put keys, tokens or credentials in the policy.

Restore policy is deliberately strict:

- `purge_floor` must be `retain_and_verify_before_restore`; restoring provider
  bytes without the retained non-resurrection floor is refused by policy.
- `old_key_retirement` must be `after_backup_reconciliation`; old KMS versions
  remain available until provider rotation and independent backup
  reconciliation are complete.

This gate prevents a production-labelled process from silently using the
development plaintext profile. It does not establish FIPS certification,
forensic erasure, production Vault/HSM/IAM qualification, or encryption of
copies outside the declared roots.

