# Research Log: Token-efficient agent-to-agent communication for wire
Started: 2026-05-26
Cutoff used: 8 weeks (open-source/project), 4 weeks for model-perf claims; foundational method papers treated as durable findings (flagged where aging).
Cutoff rationale: mix of fast-moving AI research + durable architectural facts.

| # | Claim | Source | Date | Tier | Score | Stale? | Notes |
|---|-------|--------|------|------|-------|--------|-------|
| 1 | Text embeddings are substantially invertible: vec2text recovers 92% of 32-token sequences, BLEU 97.3, via a T5 encoder-decoder w/ iterative correction | arxiv 2310.06816 "Text Embeddings Reveal (Almost) As Much As Text" (Morris et al.) | 2023-10 | P (academic) | 70 | aging (>12mo) but finding durable + reproduced (arxiv 2507.07700, 2025) | CORRECTS my earlier "embeddings not invertible". Requires model-SPECIFIC trained inverter; degrades on longer/precise text. |
| 2 | Inversion is model-specific + degrades with length | same + thegradient.pub/text-embedding-inversion | 2023-2025 | P/S | 65 | no | "Almost" in the title is load-bearing; long precise content not recoverable. |
| 3 | A2A protocol = JSON-RPC 2.0 over HTTPS; optional REST HTTP+JSON; SSE streaming; metadata is JSON | a2a-protocol.org/latest/specification + github a2aproject/A2A | 2025 (v0.3.0/draft v1.0) | P | 90 | no | The interop standard wire speaks externally is TEXT/JSON, not vectors. |
| 4 | Latent inter-agent comms is real + beneficial: Interlat passes continuous last hidden states; up to 24x inference speedup, beats CoT prompting | arxiv 2511.09149 "Enabling Agents to Communicate Entirely in Latent Space" | 2025-11 | P (academic) | 75 | no | CORRECTS my earlier "impossible". BUT requires shared model internals (hidden states) -> homogeneous/co-designed agents. |
| 5 | Activation-passing between LM agents is an active technique | arxiv 2501.14082 "Communicating Activations Between Language Model Agents" | 2025-01 | P | 72 | no | Same constraint: model-internal access. |
| 6 | Anthropic prompt caching: cache-hit = 0.1x base input price (90% reduction); 5-min write 1.25x, 1-hr write 2x; ~85% latency cut on long prompts | platform.claude.com/docs prompt-caching + pricing | 2025 | P | 90 | no | Token-efficiency lever for repeated scaffolding; content-addressed dedup complements it. |
| 7 | Hosted LLM input interface is tokens, not vectors (no raw-embedding input surface) | API design (Anthropic/OpenAI), common knowledge | n/a | P | 90 | no | Decisive blocker for "embeddings-only" across hosted models. Common knowledge, low contest. |
| 8 | wire transports signed JSONL events keyed by `kind`; agent-card carries capabilities; A2A served on .well-known | wire repo (PROTOCOL.md, AGENT_INTEGRATION.md), this session | 2026-05 | P | 95 | no | `kind` is already an intent-code surface; capabilities is the negotiation surface. User-authoritative. |

## Conflicts
- My own prior turn's framing ("embeddings not invertible", "latent comms impossible") vs sources #1/#4: sources win. RFC corrects both: invertible-but-model-specific-and-lossy; latent-real-but-homogeneous-only.

## Trust-prior caveats
- #1 is aging (2023) but the FINDING (embeddings carry recoverable text) is reproduced 2025 (#1 notes) → durable, scored 70 as primary-academic.
- #4/#5 are 2025 frontier academic — real direction, not yet production-standard; scored 72–75, framed as future/out-of-scope for the cross-vendor path.
