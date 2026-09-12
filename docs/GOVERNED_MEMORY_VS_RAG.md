# Governed memory is not RAG

Retrieval-augmented generation ranks text by embedding similarity and
injects the nearest chunks. That is a useful index. It is not an
authorization, provenance or truth model.

CCOS Enterprise treats similarity as a **shortlist**, never as authority:

| RAG default | CCOS governed memory |
| --- | --- |
| Nearest chunk wins | Only `Active` assets with recall-eligible trust may enter context |
| Chunk text is anonymous | Every chunk keeps `MemoryAssetId`, lineage and evidence refs |
| Restart loses or re-trusts state | Durable projection reconstructs lineage, trust and loadout |
| Contradiction is just another neighbor | Disputed/quarantined assets are refused, not ranked |
| Query mutation can rig the benchmark | Eval labels are implementation-faithful; noisy traps live in the corpus |

The served path is:

1. tenant + loadout (which spaces may be read);
2. bounded provider recall;
3. lineage/trust admission;
4. item/byte context budget;
5. attestation: *why* each surviving chunk is eligible.

Similarity may order step 2. It cannot skip steps 3–5.
