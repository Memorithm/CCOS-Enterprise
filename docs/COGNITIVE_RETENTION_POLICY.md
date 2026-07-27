# Cognitive Retention Policy

- Retention classes per tenant: ephemeral context, episodic journal,
  sealed snapshots, compliance archives.
- Deletion = invalidation in Core semantics: the current fold forgets, the
  sealed history remains auditable where the retention class requires it.
- Expired retention classes are enforced by policy evaluation, not cron
  conventions — every enforcement writes an audit event.
