# SML retrieval — bras concurrent (GROK-ICM) — 2026-10-29

Statut : **backend SML réel branché (opt-in), toujours `NotBeirValidated`**. Aucune métrique,
aucun claim de performance. (Historique : contrat livré en #241 avec backend indisponible.)

## Mise à jour — backend sigpage-v0 (feature `sml-backend`)

- Dépendance optionnelle `sml-core` (SML-GENIUS), **git pin rev `538d17da`** (#762), feature
  `icm-rank`, même schéma de pin que `octasoma`. `deny.toml` : dépôt git autorisé + exception
  licence PolyForm-Noncommercial pour `sml-core` (comme `scirust-license`).
- Feature `sml-backend = ["concurrent-arm", "dep:sml-core"]`, défaut off. Sans elle, rien ne change
  vs #241 : seul `UnavailableSmlRetrieval` existe (test `tests/feature_off.rs`).
- `SmlSignaturePageAdapter` : un `SignaturePageRanker` par tenant (isolation par index),
  conversion `RankedList` → `SmlRetrievalCandidate`, filtrage loadout avant troncature `k`,
  scores non finis refusés, vérification `arm_id == sml-grok-icm-concurrent`, statut
  `NotBeirValidated` propagé (`validation_status()`, `last_validation_status()`). Passe ensuite par
  `GovernedSmlRetrieval` et `admit_governed_recall` (tests `tests/sml_backend.rs`, corpus jouet :
  tests de contrat, pas de qualité).
- Sélecteur MCP `memory.document_recall` : **non branché**.
- Étape suivante : campagne BEIR selon la prereg SML #761 (`6fe51bee`), seuils figés avant run,
  négatifs conservés. Non lancée ici.

## Décision

- Crate `crates/ccos-enterprise-sml-retrieval` (Enterprise uniquement, rien vers Core).
- Trait `SmlRetrievalAdapter` : requête texte + `TenantId` + `MemoryLoadout` explicite →
  `SmlRetrievalCandidate { asset_id, space, payload, score }` → `GovernedMemoryObservation`
  (doit toujours passer `admit_governed_recall`).
- Wrapper `GovernedSmlRetrieval` derrière la feature `concurrent-arm` (défaut off) :
  requête vide refusée, `k = 0` ne touche pas le backend, fail-closed sur espace hors loadout,
  score non fini, `asset_id` dupliqué ; tri stable score desc puis id asc ; troncature `k`.
- Label de bras figé : `SML_CONCURRENT_ARM_ID = "sml-grok-icm-concurrent"`.
- `DocumentMemory` / `GovernedDocumentMemory` / `memory.document_recall` **inchangés** :
  lexical par défaut, fused MiniLM validé (#239/#240). Le bras SML est un choix explicite, jamais
  un remplacement silencieux.
- Aucune dépendance GPU / NVIDIA ; aucune dépendance à SML-GENIUS pour l'instant.

## Cartographie

- CCOS : point de branchement = à côté de `GovernedDocumentMemory::recall_documents`
  (`ccos-enterprise-docmemory`), même forme de sortie, même passage `admit_governed_recall`.
  Côté serveur MCP, un futur sélecteur de bras pour `memory.document_recall` (non fait ici).
- SML-GENIUS `main` @ `d9ba318` : GROK-ICM = `sml_core::icm_guard::GuardedPage`
  (SECDED(72,64) + CRC-32, feature `icm`). C'est une couche d'**intégrité** de pages ; il
  n'existe **pas** d'API requête texte → documents classés. D'où `UnavailableSmlRetrieval`, qui
  renvoie `BackendUnavailable` (erreur, jamais une liste vide ni des scores fabriqués).
- Architecture indépendante : ni ternary/hybrid (ligne Claude) ni skyrmion (ligne GPT).

## Suite (non démarrée)

1. ~~API de ranking SML~~ (fait : SML #761/#762).
2. ~~Adapter + dépendance optionnelle pin SHA~~ (fait : feature `sml-backend`).
3. Prereg campagne CCOS : bras `sml-grok-icm-concurrent` vs `DocumentMemory` fused sur les mêmes
   splits BEIR, seuils figés avant run ; négatifs conservés.
4. Seulement après run : éventuel sélecteur de bras dans `memory.document_recall`.
