# SML retrieval — bras concurrent (GROK-ICM) — 2026-10-29

Statut : **contrat livré, backend indisponible**. Aucune métrique, aucun claim de performance.

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

1. SML-GENIUS : définir une API de ranking GROK-ICM propre (prereg côté SML d'abord).
2. Implémenter `SmlRetrievalAdapter` pour elle, dépendance SML optionnelle sous feature, pin SHA.
3. Prereg campagne CCOS : bras `sml-grok-icm-concurrent` vs `DocumentMemory` fused sur les mêmes
   splits BEIR, seuils figés avant run ; négatifs conservés.
4. Seulement après run : éventuel sélecteur de bras dans `memory.document_recall`.
