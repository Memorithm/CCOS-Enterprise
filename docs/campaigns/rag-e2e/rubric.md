# RAG E2E v1 adjudication rubric

The reviewer sees one packet row at a time: the question, the gold answers (or "UNANSWERABLE"),
the answer text, and every cited quote. The reviewer does not see the arm. For each row, record:

1. `answer_correct` (true/false).
   - Answerable question: true iff the answer is semantically equivalent to at least one gold
     answer. Paraphrases and formatting differences count; partial or extra contradictory content
     does not.
   - Unanswerable question: true iff the system abstained.
   - Runtime error rows (shown as abstentions): judge by the same rules. The scorer separately
     prevents a runtime failure from earning task or abstention success.
2. `total_claims` (integer): number of atomic factual claims in the answer. 0 iff the system
   abstained; at least 1 for any non-abstention.
3. `supported_claims` (integer, 0..total_claims): claims entailed by at least one cited quote.
   Claims without a citation, or entailed only by world knowledge, are unsupported.

Do not consult other rows, the retrieval ranking or outside sources. Record disagreements with the
rubric in a free-text `note`; never change a judgment to fit an expected outcome.
