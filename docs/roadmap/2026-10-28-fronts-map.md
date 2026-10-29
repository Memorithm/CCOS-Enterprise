# CCOS-Enterprise — carte des fronts (2026-10-28)

Règle: aucun gain n'est revendiqué sans prereg mergé + CI verte + résultats publiés (négatifs gardés).

| # | front | état | métrique de succès | prochain levier | dépendance |
|---|---|---|---|---|---|
| 1 | Retrieval docs (BEIR) | **prouvé (SciFact seul)**: fused MiniLM α=0.5 vs BM25 Δ=+0.0521 nDCG@10 (#227/#228/#230). Dense seul NS, PRF v2 négatif, v1/v2 négatifs | nDCG@10 test, Δ≥+0.01 et IC95 bas>0 (seeds 1-3) par dataset | v4 multi-dataset NFCorpus+FiQA, v3 gelé (prereg #231) | aucune (CPU) |
| 2 | Mémoire gouvernée (ConformalGuard, promotion, audit) | **partiel**: `ConformalGuard` n'est utilisé que par `injection_classifier` (core); promotion/provenance/attestation existent dans `ccos-enterprise-memory` mais sans lien avec `DocumentMemory` | taux de fausses alarmes ≤ α mesuré sur jeu bénin tenu à part; 0 recall non gouverné sur le chemin produit | brancher le guard sur l'ingest documentaire + test de couverture | front 3 |
| 3 | Intégration produit (ingest → DocumentMemory) | **bloqué / gap**: `DocumentMemory` n'est utilisé que dans des exemples de campagne (`core/examples/beir_campaign_v2.rs`, `crates/ccos-dense-encoder/examples/beir_campaign_v3.rs`). Aucun impl de `SemanticMemoryProvider` / `GovernedSemanticMemoryProvider` ne le porte; `ccos-enterprise-ingest` n'y écrit pas | requête via l'API recall gouvernée → mêmes classements que la campagne (test de parité) | adaptateur `DocumentMemory` → `SemanticMemoryProvider` dans un crate Enterprise (encodeur injecté), puis admission via `admit_governed_recall` | décision d'architecture (où vit l'index, persistance) |
| 4 | Adapter SML-GENIUS retrieval | **non commencé** (volontairement) | même protocole BEIR, vs baseline CCOS v4 | après verdict v4 | front 1 (baseline multi-dataset) |
| 5 | RAG E2E (générateur + adjudication) | **bloqué** | exactitude réponse adjugée en aveugle, prereg | choix générateur + adjudicateur + budget | fronts 1 et 3 |
| 6 | Perf runtime / GPU portable | **partiel**: encodeur pure Rust CPU ≈16 textes/s (8 cœurs); 64k textes FiQA ≈1 h | textes/s et latence p95 recall à qualité identique (parité cos>0.9999) | batching/SIMD ou backend GPU optionnel (non NVIDIA-obligatoire), lien SML possible | front 1 (oracle de parité) |

## Audit câblage (gap exact)

- `core/src/doc_memory.rs`: `DocumentMemory<E: Encoder>` (lexical/dense/fused/PRF). Consommateurs: exemples seulement.
- `core/src/memory/ports.rs`: trait `SemanticMemoryProvider::recall` — aucune implémentation non-test trouvée dans le workspace.
- `crates/ccos-enterprise-memory`: `GovernedSemanticMemoryProvider`, `admit_governed_recall`, promotion, provenance — ne référencent pas `DocumentMemory`.
- `core/src/conformal.rs`: `ConformalGuard` — seul appelant `core/src/injection_classifier.rs`.
- Câblage non fait dans cette PR: il exige des choix (persistance de l'index, tenant scoping, budget d'encodage à l'ingest) qui ne sont pas « sûrs » sans revue. Proposition: PR dédiée avec adaptateur + test de parité campagne↔API.

## Mise à jour 2026-10-29 — câblage front 2/3 (crate `ccos-enterprise-docmemory`)

- **Branché**: `GovernedDocumentMemory` (nouveau crate Enterprise, Core inchangé) porte `DocumentMemory` derrière `TenantScope` + `MemoryLoadout`; une partition `(tenant, space)` = un `DocumentMemory` (stats BM25 et vecteurs isolés). Encodeur injecté par fabrique (même encodeur que la campagne possible). Sortie = `GovernedMemoryObservation` (asset id CCOS) → doit passer `admit_governed_recall`.
- **Test de parité**: loadout mono-espace ⇒ ids, scores et payloads identiques à `DocumentMemory::rank` (lexical, dense, fused). Ce n'est pas une mesure BEIR; aucune métrique nouvelle n'est revendiquée.
- **ConformalGuard à l'ingest**: optionnel (`IngestGuard`), scoreur de non-conformité injecté; document flaggé (ou score NaN) refusé avant indexation; guard non calibré (seuil `+∞`, fail-open côté Core) refusé à la construction. Texte vide refusé (leçon FiQA). Le taux de fausses alarmes ≤ α sur jeu bénin tenu à part reste **à mesurer** (pas de scoreur produit choisi).
- **Reste bloqué**: `ccos-enterprise-ingest` n'appelle pas encore l'adaptateur (choix: déclencheur à la promotion vs à l'ingest, budget d'encodage); persistance de l'index (actuellement en mémoire, reconstructible depuis les assets gouvernés); exposition via le gateway/MCP recall.

## Mise à jour 2026-10-29 (suite) — `ccos-enterprise-ingest` → `GovernedDocumentMemory`

- **Branché**: module `ccos_enterprise_ingest::doc_index` (`index_artifact`, `ingest_and_index`, `lexical_only_memory`). Core inchangé.
- **Déclencheur (décision)**: indexation juste après un `fetch` réussi (artefact tenant-scopé, épinglé par hash), pas à la promotion — chemin le plus court pour fermer ingest → index → recall gouverné. L'asset id est stable (`artifact:<source_id>`), donc un déclenchement à la promotion reste possible plus tard sans changer l'index. Option écartée pour l'instant: indexer à la promotion (exige un hook dans `ccos-enterprise-promotion`, absent aujourd'hui).
- **Budget d'encodage (décision)**: opt-in. `lexical_only_memory()` = BM25 seul (`LexicalOnly`, aucun vecteur). Dense/fused = encodeur injecté par l'appelant; aucun modèle imposé.
- **ConformalGuard**: optionnel, construit par l'appelant avec un scoreur calibré (`GovernedDocumentMemory::with_guard`); jamais construit par défaut. Refus (vide, non UTF-8, flaggé) remontés dans `IndexReport.refused`, jamais indexés.
- **Tests**: ingest → index → `admit_governed_recall` (lignage = evidence artefact), isolation tenant/espace, refus doc vide et non UTF-8, encodeur dense injecté + guard. Aucune métrique revendiquée.
- **Reste ouvert**: persistance de l'index; exposition gateway/MCP recall; écart entre `GovernedSemanticMemoryProvider` (embedding) et l'API texte; taux de fausses alarmes ≤ α du guard à mesurer sur un jeu bénin tenu à part; ingestion orchestrée (journal P0 + indexation dans une même transaction) non implémentée.
