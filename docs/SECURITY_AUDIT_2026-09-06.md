# Security Audit — CCOS-Enterprise

- **Date** : 2026-09-06
- **Commit audité** : `62f99a7` (branche `main`)
- **Dépôt** : `Memorithm/CCOS-Enterprise`
- **Périmètre** : ~40 crates Rust (264 fichiers), Core inclus (subtree), outils + CI
- **Méthode** : build/tests locaux, audits de dépendances (cargo-audit, cargo-deny), scan secrets/unsafe, 4 revues de sécurité approfondies (gateway/MCP, auth/RBAC, runtime/admission, gouvernance/serveur de licences)
- **Conformité AGENTS.md** : roadmap `agent/ecosystem-roadmap` récupérée et lue avant l'audit et avant les correctifs. Audit lecture seule ; les correctifs qui suivent respectent les invariants ENT0–ENT2.

## 1. Santé du build

| Vérification | Résultat |
|---|---|
| `cargo check --workspace --all-targets` | ✅ Succès |
| `cargo test --workspace` | ✅ 1 572 tests passés, 0 échec |
| `cargo clippy -D warnings` | ✅ 0 warning |
| `cargo fmt --check` | ✅ Propre |
| `cargo audit` (RustSec, 1 239 advisories, 297 deps) | ✅ 0 vulnérabilité |
| `cargo deny check` | ✅ advisories / bans / licences / sources OK |
| Scan secrets / clés privées | ✅ Rien |
| `#![forbid(unsafe_code)]` | ✅ Quasi-totalité des crates |
| CI (ci-security, ci-full) | ✅ solide (cargo-deny, gitleaks épinglé + checksum, scan de capacités interdites) |

## 2. Anomalies

### HIGH

- **H-1** — RBAC indexé par nom d'acteur nu dans un `RoleBook` global → fuite de privilèges inter-tenant (`ccos-enterprise-rbac/src/lib.rs:23,157` ; intégration `ccos-enterprise-runtime/src/lib.rs:574,1601`). Un `agent-7` de l'org A hérite des rôles du `agent-7` de l'org B.
- **H-2** — `revoke_actor` n'atteint jamais les identités mTLS : `MtlsAuthenticator` ne consulte pas `Revocations` (`ccos-enterprise-auth/src/mtls.rs:126-204`).

### MEDIUM

| # | Anomalie | Localisation |
|---|---|---|
| M-1 | Seed d'émetteur passable en argv/env → lisible via `ps`//proc | `mcp/src/bin/ccos-enterprise-gen-token.rs:46,110,220` |
| M-2 | Révocation/replay par processus en mémoire → fail-open multi-réplica | `auth/src/lib.rs:78`, `revocation.rs:56` |
| M-3 | `AuthenticatedActor` dérive `Serialize/Deserialize` (porte de falsification) | `auth/src/lib.rs:164` |
| M-4 | `VerifiedPeer::attested` constructeur public non contraint | `auth/src/mtls.rs:74` |
| M-5 | API stockage `pub` (`put/get/clear_cells`) contourne les 9 gates, cross-tenant | `runtime/src/lib.rs:1295-1383` |
| M-6 | Quota OctaSoma en items, pas en octets → DoS mémoire noisy-neighbor | `octasoma/src/lib.rs:207-239` |
| M-7 | Restore/promotion backup sans authentification ; `writes_frozen` jamais lu par l'admission | `backup/src/lib.rs:569,664,802-914` |
| M-8 | PHP : `vault.json`/`rate.txt` 0644 en mutualisé ; `seed.hex` non vérifié | `tools/ccos-license-server/php/claim.php:220,241` |
| M-9 | Listes de révocation : `expires_at` optionnel ; enforcement runtime non prouvé | `governance/src/vendor.rs:183,214` |
| M-10 | TOCTOU daemon/CLI sur `vault.json` (pas de lock) → révocations écrasées | `tools/ccos-license-server/src/lib.rs:511-526,583,601` |
| M-11 | PHP : `php://input` illimité avant rate-limit → DoS | `php/claim.php:342-344` |

### LOW

- **L-1** — `ReplayGuard::witness` scan O(n) sous mutex (`revocation.rs:241`)
- **L-2** — Tokens multi-`aud` acceptés sans check `azp` (`oidc.rs:131`)
- **L-3** — mTLS ne vérifie pas `not_before` (`mtls.rs:58,185`)
- **L-4** — Serveur stdio : appels « admitted mais en échec » effacés du ledger gouvernance (`bin/ccos-enterprise-mcp-server.rs:1571-1634`)
- **L-5** — `promote_staged` fait confiance au tenant du manifeste staged (`backup/src/lib.rs:665`)
- **L-6** — Manifests v1 : noms de segments non authentifiés (`backup/src/lib.rs`)
- **L-7** — Horloge pré-epoch → expiration d'approbation fail-open (`runtime/src/lib.rs`)
- **L-8** — `replay_memory=0` désactive le gate replay ; part par tenant décroissante (`runtime/src/lib.rs`)
- **L-9** — Store de cells : 64 GiB/tenant, pas de plafond global (`runtime/src/lib.rs`)
- **L-10** — Réponses token sans `Cache-Control: no-store` (`tools/ccos-license-server/src/lib.rs:899`)
- **L-11** — HTTPS imposé seulement par `.htaccess` (`php/claim.php`)
- **L-12** — `CCOS_MACHINE_ID` contourne le binding mono-poste (`governance/src/claim.rs:178`)
- **L-13** — Versions pré-release comparées égales (confusion downgrade) (`governance/src/release.rs:118`)

### INFO (traités si peu coûteux)

Issuer mismatch rapporté `WrongAudience` (`oidc.rs:212`) ; `TenantId` non validé à la construction (`tenancy.rs:12`) ; seed en env / code sur stdout (`gen-token`) ; `cost_tokens` fourni par l'appelant ; `AdminAction.actor` non authentifié.

## 3. Points forts vérifiés

- Gateway allowlist deny-by-default : aucune bypass trouvée (alias/unicode/casse/séparateurs testés).
- Chemin d'admission « nine-gate » : ordre documenté respecté, fail-closed, refusals à coût nul, replay borné, arithmétique saturante.
- Crypto : ed25519 uniquement, signature avant parse de claims, CSPRNG partout, zéro clé par défaut, fichiers secrets 0600 no-clobber (Rust).
- Serveur HTTP de licences : parser durci (anti-smuggling), deadlines, shed de connexions.
- Backup : traversée de chemins impossible par construction, digests v2 à séparation de domaine, générations immuables.
- Observabilité bornée (4 096 séries, injection d'étiquettes bloquée).
- OIDC refuse RS256 (RUSTSEC-2023-0071) — cohérence supply-chain.

## 4. Statut des correctifs

> Mis à jour après la passe de correction (voir historique git).

| Anomalie | Statut | Correctif |
|---|---|---|
| (à remplir après la passe de correction) | | |
