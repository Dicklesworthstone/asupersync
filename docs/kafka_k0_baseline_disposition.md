# Kafka K0.5 baseline disposition

<!-- BEGIN KAFKA K0.5 BASELINE DISPOSITION -->

This is the operator companion to
`artifacts/kafka_k0_baseline_disposition_v1.json`. It aggregates the four
source-pinned Kafka K0 child packets without upgrading static inventory into
execution evidence. The baseline disposition is `KEEP_INCUMBENT`. Work already
approved under the native Kafka investigation may continue only as an additive
investigation beside the incumbent; this receipt does not authorize replacing,
removing, weakening, or bypassing the incumbent path.

No compiler, formatter, test, broker, runtime, service, container, remote job,
external search, or network lane was run to create this packet. Its evidence is
static repository inspection, exact child-packet hashes, and deterministic
cross-artifact projections only.

| Aggregate field | Exact value |
|---|---|
| `artifact_id` | `kafka-k0-baseline-disposition-v1` |
| `bead_id` | `asupersync-dep-p7-kafka-removal-sarszu.1.5` |
| `program_id` / `capability_id` | `asupersync-ir2uf0` / `CAP-KAFKA` |
| `baseline_revision` | `d4db2d3f072bd92281f35829dc1a5c92bc69f376` |
| `inventory_state` | `K0_5_AGGREGATE_FROZEN_KEEP_INCUMBENT` |
| `policy.mode` | `STATIC_ONLY_FAIL_CLOSED` |
| `policy.canonicalization_id` | `KAFKA_K0_5_CANONICAL_PROJECTION_V1` |

## Child packet authority

The child revisions are sequential source snapshots, not revisions that are
expected to equal one another. K0.5 freezes every child by its own revision and
content hash.

| Child | Machine packet | Baseline / authority revision | Packet SHA-256 | Frozen state |
|---|---|---|---|---|
| K0.1 | `kafka-capability-inventory-v1` | `2d811170e956966e960db122a0d634a5b60c56e0` / same | `5dfe71df6daaa056f8f4d22d08fa934b5398baeeff0d5ff27eb0f544405251d6` | `K0_1_SOURCE_REACHABILITY_FROZEN` |
| K0.2 | `kafka-incumbent-semantics-matrix-v1` | `b4997e8fe4de098a5a30ff468418460b59ca414a` / same | `fec9ac1a1e9ac63ce25393962c843f9169cae804c16c470ada2bf670ab0fc4ec` | `K0_2_INCUMBENT_SEMANTICS_FROZEN` |
| K0.3 | `kafka-downstream-user-journey-inventory-v1` | `ae22e710d87412b38e546b32e9702106619481d5` / same | `52f8dc9a2695a170b14c85c9b29b6e60f95e05bd013d3d9db0dab8d94a1ced09` | `K0_3_LOCAL_STATIC_AND_CALL_SITE_CENSUS_FROZEN_EXTERNAL_UNKNOWN` |
| K0.4 | `kafka-broker-fixture-provenance-matrix-v1` | `012c13714db267a4fba928db9f900b70d6c1d25a` / top-level `authority_revision` absent | `03406fe1146345ef7c50ec5e4077f0c6131db963e3776215629e9d34a781a643` | `K0_4_STATIC_FIXTURE_AND_PROVENANCE_MATRIX_FROZEN_RUNTIME_UNKNOWN` |

The missing K0.4 top-level `authority_revision` is retained as an explicit
fail-closed schema difference. K0.5 uses the K0.4 `baseline_revision` and packet
hash; it does not invent an authority revision. All four child source-pin maps
matched the live repository during this static reconciliation.

## Coverage projection

The primary stable-ID receipt contains 903 unique IDs. Of these, 892 are core
definitions and 11 are K0.4 contradiction evidence-input IDs. The 127 K0.3
authority-reference disposition rows are typed joins and are deliberately not
counted as new definitions.

| Projection | Exact count | Composition |
|---|---:|---|
| K0.1 primary IDs | 96 | 13 source pins, 13 profiles, 30 public symbols, 6 backend bindings, 8 cfg branches, 11 no-feature behaviors, 15 routed gaps |
| K0.2 primary IDs | 147 | 8 source pins, 17 profile groups, 97 semantics, 2 explicit absences, 23 routed findings |
| K0.3 primary IDs | 469 | 225 pins, 5 occurrence dispositions, 4 non-consumer dispositions, 7 queries, 15 consumers, 34 local rows, 16 atomic cases, 31 documentation claims, 17 profiles, 8 cells, 15 journeys, 6 evidence claims, 7 external searches, 8 owned unknowns, 23 gaps, 48 call-site groups |
| K0.4 primary IDs | 191 | 180 core IDs plus 11 contradiction inputs; core includes 20 direct pins, 8 fixture profiles, 67 fixtures, 8 environments, 36 vectors, 6 claims, 9 owned unknowns, and 26 gaps |
| Core definitions | 892 | K0.1 96 + K0.2 147 + K0.3 469 + K0.4 core 180 |
| All primary IDs | 903 | 892 core definitions + 11 contradiction inputs; all unique |
| Public-surface projection | 30 | every K0.1 `symbol_id` has one K0.3 disposition join |
| Incumbent-semantics projection | 97 | 43 configuration + 7 enum + 38 operation + 9 helper rows; every ID has one K0.3 disposition join |
| Downstream journey projection | 15 | source-pinned K0.3 user journeys |
| Fixture projection | 67 | 48 K0.3-inherited pins + 19 K0.4-direct pins across 8 fixture profiles |
| Broker/build projection | 36 | 3 locked-dependency + 5 native-build + 7 broker/API + 5 compression + 6 transport/auth + 4 topology + 6 fault/lifecycle vectors |
| Child claims projection | 93 | 6 K0.1 no-claims + 8 K0.2 no-claims + 31 K0.3 documentation claims + 6 K0.3 evidence claims + 14 K0.3 no-claims + 6 K0.4 evidence claims + 22 K0.4 no-claims |
| Aggregate claims | 7 | source reachability, semantics, downstream, provenance, migration eligibility, incumbent disposition, and native scope |

The child identity tuple digest is
`93041f25c12357a263403a447f289e125b64213c8b77a8710791e9e0054e9298`.
The ordered four-packet hash-manifest digest is
`ec3dc7ca4d040d61261fd8d5c1e7c2a661303c40ad4d6be1f3ab0ab58a9d107a`.
The ordered child documentation/contract manifest digest is
`21ef550bbc8c516ceb9e81595c4b3c30ae70243106bd044c4f9e2e7898c8031d`.
These are aggregation inputs; the machine packet owns the canonical primary-ID,
join, claims, UNKNOWN/BLOCKED, and route digests.

The canonical machine projections are:

| Projection | Count | SHA-256 |
|---|---:|---|
| Source-pin canonical JSON | 266 | `7942a3af6873d33ce06fd3c7f791e3cf06a699e94d52f842e1b821cfb6173967` |
| Unique source-pin paths | 247 | `d5631183e1560d87aeb50ca953d836b4405110b30f81c98aab099c6a5f1eb4c3` |
| Source-pin overlap paths | 15 | membership is bound by the 34-row projection below |
| Source-pin rows on overlap paths | 34 | `a3282475b61dc733ee973b7743578c938f4e07514c16b30f7ca83a0fdccd965b` |
| Core typed definitions | 892 | `43d9deb2ff6bfa772ec058e8e32e4eb4fb3be099d93c3b152685721be05d4eea` |
| Contradiction typed inputs | 11 | `60a656176b398a9b045b8c5cc1c2f2cede611683d3330c2a519a70ebf9bb72f0` |
| All primary typed IDs | 903 | `38eb986feff75d2e1e172e444e7d488c765ab42910b6b470056852dea3b0cb6e` |
| Public-symbol ID set | 30 | `307956cfcb2a4e1de2b1a45d9db3767aa88e5be090815bc9ae1a77c8ad3add28` |
| Semantic ID set | 97 | `a9967c47346ee6386e9e8836d73e819a784f829baa6d255eb24e55aae1950cf7` |
| Downstream-journey ID set | 15 | `c5a9f1947a5ecf55898c61414bb39bf753cd236fe33157083994acd63176367f` |
| K0.4 vector ID set | 36 | `73491562ae3df3f7ea6729c30834cf3cb134a002ec5d682255277df5e508e73f` |
| Fixture ID set | 67 | `bb8f922cc63f97efcfb0c76a6e26fdf923775650af8cd613f50da55c95cbb376` |
| Fixture path set | 67 | `d9542095b391dbd44a0f8d855d6cfb87e41b981642430a0de662a2965ad26db0` |
| Fixture-profile ID set | 8 | `b1848945221e425d78007ee47bced23e62b700a5e43fc6a8300124d42c8d8d09` |
| Environment ID set | 8 | `372de832a4de112e3ee8bc45b3af978d749b24c3f825416bd8e8b2d4523d831e` |

The 266-row source-pin digest wraps each row with `child`, `collection`, `id`,
and `row`, orders those wrappers by child, collection, and ID, recursively sorts
object keys, emits compact JSON, and appends one LF per record. The 34-row
overlap digest uses the separately declared
`path<TAB>child<TAB>pin_id<TAB>sha256` tuple rule.

## Sanctioned joins and collision disposition

There is no accidental exact collision among the 903 primary stable IDs. The
following repetitions are required, typed authority joins:

| Join class | Exact cardinality | Disposition |
|---|---:|---|
| K0.1 public symbols to K0.3 dispositions | 30 ID groups / 30 rows | `SANCTIONED_AUTHORITY_REFERENCE` |
| K0.2 semantics to K0.3 dispositions | 97 ID groups / 97 rows | `SANCTIONED_AUTHORITY_REFERENCE` |
| Combined definition-ID reference groups | 127 groups / 127 rows | exact joins, not duplicate definitions |
| K0.1 profiles to K0.3 compilation profiles | 13 source IDs / 17 target rows | separate many-to-one typed mapping, not part of the 127 collision groups |
| K0.3 source pins to K0.4 fixture census | 48 referenced pins / 48 fixture rows | inherited fixture-pin join, not a definition collision |
| K0.4 direct pins to fixture census | 19 referenced pins / 19 fixture rows | the twentieth direct pin is the K0.3 authority artifact |
| Fixture profiles to fixture census | 8 profiles / 67 fixture rows | exact typed reference join |
| K0.3 lexical exclusions | 34 groups / 232 sites | `NON_KAFKA_LEXICAL_EXCLUSIONS`, not Kafka definition collisions |

The four K0.1 profiles intentionally used twice by K0.3 are
`KAFKA-PROFILE-DOWNSTREAM-NO-KAFKA`,
`KAFKA-PROFILE-NATIVE-KAFKA-RELEASE`,
`KAFKA-PROFILE-TEST-INTERNALS-NO-KAFKA`, and
`KAFKA-PROFILE-UNIT-WITH-KAFKA`. The K0.1 13-profile ID-set digest is
`882b6f73ee7c5abfe73080804fcd082c05dddd9c4002ee61ff9336f0a0d439eb`.
The 17-row profile mapping digest is
`535d71b0db091352aa1b1df6418af9f0989b34c7c89584fe5e15b3614dce0438`.
It serializes `k0_1_profile_id<TAB>profile_id`, bytewise-sorts unique rows, and
appends one LF each.
The 67-row fixture-pin mapping digest is
`f0200bd742a0a7a6374cd7dc87d9b1832c8f6d5a79e1f363db6464acfbe2bba2`,
and the fixture-profile mapping digest is
`0c1a77c6b9db4bc3efc478ba4313a65193ab849f7020d5f1f3b2fa4d73c1be9d`.
The former serializes `pin_origin<TAB>source_pin_id<TAB>fixture_id<TAB>path`;
the latter serializes
`classification_profile_id<TAB>fixture_id<TAB>path`. Both bytewise-sort unique
rows and append one LF each.
The combined 127-row authority-reference mapping digest is
`0a88e36135222e48bfeab5095be3896ef946cc9fa05f38cbd19d2cb656107cf9`;
its combined ID-set digest is
`a2336ba563186e1bc4a0a935ced3731e2292e8a6d54b0858311662113b267a94`.
The mapping tuple is
`left_child<TAB>left_collection<TAB>id<TAB>K0.3<TAB>right_collection<TAB>id`,
bytewise-sorted with one LF per row.
The lexical-exclusion mapping digest is
`c1808f3d8ce85fc70642af0424653f0bb287a71998774c9206b80172f8e175db`.
For each `EXCLUDED_NAME_COLLISION` atomic site, it recursively key-sorts and
compactly serializes an object containing the parent `group_id`, parent `path`,
and complete site object, bytewise-sorts the 232 records, and appends one LF
each.
K0.5 keys identity by typed section and exact ID; it does not infer type from
prefix width, prefix spelling, or case.

## UNKNOWN and BLOCKED disposition

`UNKNOWN` and `BLOCKED` mean accounted, owned, fail-closed work. They never mean
supported, passing, absent, removable, or complete. A missing row, missing owner,
broken join, changed child hash, or unresolved state outside these projections
blocks the receipt rather than becoming another accepted UNKNOWN.

| Source group | Rows | Downstream authority |
|---|---:|---|
| K0.3 K0.1 usage dispositions | 13 `UNKNOWN` | K14.1 claim-time refresh and synthesis |
| K0.3 K0.2 usage dispositions | 52 `UNKNOWN` | K14.1 claim-time refresh and synthesis |
| K0.3 external searches | 7 `UNKNOWN` / `NOT_RUN` | K14.1 |
| K0.3 unresolved documentation occurrences | 8,599 | K10.5, refreshed by K14.1 |
| K0.3 non-passing feature/platform cells | 8 | K12.5, refreshed by K14.1 |
| K0.3 owned unknowns | 8 | 7 to K14.1; immutable real-broker receipt to K13.6 |
| K0.3 exact blocked inventory/evidence rows | 24 | K10.5, K12.3, K13.6, K14.1, and the declared validation-frontier owner |
| K0.3 feature/platform aggregate | `UNKNOWN`, with real-service `BLOCKED_EXTERNAL` | K14.1 freshness plus the applicable K13 terminal |
| K0.4 fixture-profile rows | 1 blocked opt-in real-broker profile | K13.6 |
| K0.4 environment identities | 5 `UNKNOWN`/`BLOCKED` rows | resolved through the K2.1, K4.2, and K13.1/K13.3/K13.4/K13.5 vector joins |
| K0.4 executable vectors | 23 `UNKNOWN`/`BLOCKED` rows | K2.1, K4.2, K12.1, and K13.1/K13.3/K13.4/K13.5/K13.6 |
| K0.4 owned unknowns | 9 `BLOCKED` | inventory owner K0.4; resolution remains with the routed K2/K4/K12/K13 owners |

The reduced selector ledger contains 142 rows: 96 exact K0.3 state rows, 8
K0.3 `owned_unknowns` rows whose section supplies the unknown state, and 38
exact K0.4 state rows. Its static reconciliation digest is
`5c7fb727bc79d4f8be1c979fadda8bcfd261da0953e972a32a89bef27a28b18c`.
The selector scans every top-level array row in K0.3 and K0.4 for a direct
string-valued field exactly equal to `UNKNOWN`, `BLOCKED`, or
`BLOCKED_EXTERNAL`, then adds each K0.3 `owned_unknowns` row with synthetic
state `OWNED_UNKNOWN`.
For each selected row, the canonicalizer lexically sorts and deduplicates the
matched states, joins them with commas, bytewise-sorts the resulting
`stage<TAB>section<TAB>id<TAB>owner<TAB>matched-states` records, and appends one
LF per row. The 23-row K0.4 unresolved-vector ID-set digest is
`2fa4c57fe931c5528d8ec49305490f7ace1084d9d848642e3471294f342e583b`.
The separate K0.3 feature/platform aggregate is intentionally not hidden inside
that selector count.

The 17 explicit `owned_unknowns` IDs have 17 owner edges and 7 distinct
resolution owners. Their ID-set, owner-edge, and owner-set digests are,
respectively,
`33c9cdf3dca86570c906c46a902b2ec7ad8ee19aa074b0375afda36d64e63d20`,
`7b36d67eb6a635bf112838ea0104aab9b45ad918798af627ec176d01c61e554c`,
and `54a6d2f9844b771aed0b2b714d4682ea2ba40092447beeef08df0231c9e08df4`.
The owner-edge projection bytewise-sorts unique
`unknown_id<TAB>resolution_owner_bead` rows and appends one LF each.

K0.3 evidence row `KAFKA-K0-3-EVIDENCE-005` and the five blocked K0.4
environment identities do not carry a direct owner field. The evidence row
joins first through K0.3 gap `KAFKA-K0-3-GAP-007` to the included K0.4 packet,
then through K0.4 gaps `KAFKA-K0-4-GAP-009-FIXTURE`,
`KAFKA-K0-4-GAP-013-AUTH-FAULT`, and
`KAFKA-K0-4-GAP-014-TERMINAL-REAL-BROKER` to K13.1, K13.5, and K13.6; K14.1
retains claim-time refresh. The environment rows join through owned-unknown
subjects and executable-vector `environment_ids`. An implementation that
defaults any of these rows to unowned, passing, or resolved contradicts this
receipt.

## Route rollup and K0 handoff

The raw child route ledger contains 87 unique route rows, 126 owner edges, and
49 unique raw owners. The route-row, exact owner-edge, and owner-ID digests are
`efbc7795ffa4c5144ffcedf6ac2659603e9a298800b6d7130df1081d47722b43`,
`78ac2d846c8c21a1ed741ddb6a17c13c73cc57da86ae97a28577d2a061670dbc`,
and `8eb70d75bda5b08007d844cee45bca48383d875ddf795610c9e0f936d1f92e88`.
The route-row digest wraps each child row as a recursively key-sorted compact
JSON object with `child`, `collection`, `id`, and `row` fields, orders those
objects by child, collection, and ID, and appends one LF per record.
The stage counts are K0.1 15, K0.2 23, K0.3 23, and K0.4 26.
K0.1 and K0.2 spell route state as `ROUTED`; K0.3 and K0.4 omit a route-state
field. K0.5 preserves those omitted states as unresolved routed work. It never
interprets a missing state as closed.

| Internal inventory handoff | Edges | Aggregate state |
|---|---:|---|
| K0.1 to K0.2 | 6 | `SATISFIED_BY_INCLUDED_CHILD_AND_ROUTED_ONWARD` |
| K0.1 to K0.3 | 2 | `SATISFIED_BY_INCLUDED_CHILD_AND_ROUTED_ONWARD` |
| K0.1 to K0.4 | 2 | `SATISFIED_BY_INCLUDED_CHILD_AND_ROUTED_ONWARD` |
| K0.3 to K0.4 | 1 | `SATISFIED_BY_INCLUDED_CHILD_AND_ROUTED_ONWARD` |

The 11-edge internal-handoff digest is
`461050ab95066ce754a177798c2c22453a008992ff5c9c1e98d807383a240851`.
It selects edges whose owner is the included K0.2, K0.3, or K0.4 child bead,
bytewise-sorts unique `stage<TAB>gap-or-finding-id<TAB>owner` records, and
appends one LF each.
The packet also retains three standalone `inventory_input_only` routes; it has
no unresolved internal handoff, missing owner row, or unowned route row.

Raw owner edges into K0.2, K0.3, or K0.4 are internal inventory handoffs. K0.5
consumes their source-pinned facts and retains their downstream route. It does
not reopen a closed inventory child, erase the raw edge, or misrepresent the
internal handoff as terminal implementation evidence. The K0.5 receipt is the
sole K0 baseline consumed by K1 and the native epic; it is not the terminal
receipt for any later routed owner.

## Claims projection and disposition

The 93 projected child claim records preserve their source evidence classes.
Their canonical JSON digest is
`4ab07928c2f255c4f6bbe8d69561d25c413391ee84d359dead80ebf8e3ec6477`.
Each child record is wrapped with `child`, `collection`, `id`, and `row`; no-claim
rows use their zero-based array index as the ID, while claim/evidence rows retain
their declared IDs. Records are ordered by child, collection, and ID before
recursive key sorting, compact JSON emission, and one trailing LF each.
The seven aggregate claims are:

| Claim | Exact state |
|---|---|
| `KAFKA-K0-5-CLAIM-001` — source reachability | `STATIC_SOURCE_PINNED` |
| `KAFKA-K0-5-CLAIM-002` — incumbent semantics | `STATIC_SOURCE_PINNED` |
| `KAFKA-K0-5-CLAIM-003` — repository-local downstream census | `STATIC_SOURCE_PINNED_EXTERNAL_UNKNOWN` |
| `KAFKA-K0-5-CLAIM-004` — broker build and fixture provenance | `STATIC_SOURCE_PINNED_RUNTIME_BLOCKED` |
| `KAFKA-K0-5-CLAIM-005` — migration eligibility | `BLOCKED` |
| `KAFKA-K0-5-CLAIM-006` — incumbent disposition | `KEEP_INCUMBENT` |
| `KAFKA-K0-5-CLAIM-007` — native scope | `PREEXISTING_NATIVE_EPIC_INVESTIGATION_ONLY` |

The aggregate-claim projection digest is
`2a4867239016cef413e38d68bc1d788de89a23bac7ac08890632256013b4d1b6`.
It sorts claims by `claim_id`, recursively sorts each claim object's keys,
emits compact JSON, and appends one LF per claim.

In particular:

- static source, lockfile, configuration, wire-corpus, local-model, planned,
  compile-only, and proof-only rows stay in those classes;
- `NOT_RUN`, `BLOCKED`, `BLOCKED_EXTERNAL`, silent skip, mutable identity, and
  empty retained-receipt fields cannot be promoted to execution evidence;
- `current_real_broker_receipts` remains empty, and actual binary receipt count,
  executed broker evidence count, and accepted real-broker receipt count remain
  zero;
- the static K0.3 repository census does not turn its unresolved downstream,
  documentation, platform, or external-search rows into known absence; and
- the K0.4 package-source expectation does not become an actual native library,
  link-mode, host, codec, TLS, SASL, broker-version, or topology receipt.

Accordingly, the terminal baseline disposition is `KEEP_INCUMBENT`. The only
positive scope carried forward is
`PREEXISTING_NATIVE_EPIC_INVESTIGATION_ONLY`, owned by
`asupersync-dep-p7-kafka-removal-sarszu.2`. Its first contract gate is
`asupersync-dep-p7-kafka-removal-sarszu.2.1`. That additive investigation must
preserve the incumbent public facade and behavior, may use the incumbent only
within its already declared oracle/real-service boundaries, and cannot claim a
cutover from this K0 receipt.

## Terminal authorities

| Authority | Scope retained after K0.5 |
|---|---|
| K12.5 — `asupersync-dep-p7-kafka-removal-sarszu.2.12.5` | independent protocol, state, corpus, and oracle verification; `REQUIRED_NOT_PROVEN_BY_K0` |
| K13.6 — `asupersync-dep-p7-kafka-removal-sarszu.2.13.6` | terminal immutable real-service receipts and teardown; `REQUIRED_NOT_PROVEN_BY_K0` |
| K14.1 — `asupersync-dep-p7-kafka-removal-sarszu.2.14.1` | claim-time source, downstream, fixture, owner, and receipt refresh; `REQUIRED_NOT_PROVEN_BY_K0` |
| K15 — `asupersync-dep-p7-kafka-removal-sarszu.2.15` | conditional no-loss cutover or terminal KEEP; `SOLE_CUTOVER_AUTHORITY` |

K0.5 owns the terminal baseline inventory only. It does not substitute for any
of these authorities.

## No-claim boundary

This receipt does **not** prove:

- compilation, formatting, tests, fuzzing, runtime execution, broker contact,
  external search, network behavior, or service health;
- Kafka protocol correctness, request/response completeness, API-version
  negotiation, downgrade behavior, or oldest/current broker support;
- the identity, bytes, build branch, compiler, linker, `.pc` file, SONAME,
  link mode, configuration flags, or capabilities of an actually selected
  native library;
- codec availability, RecordBatch or CRC correctness, or interoperability for
  None, Gzip, Snappy, Lz4, or Zstd;
- TLS certificate validation, SASL/SCRAM authentication, credential rejection,
  secret handling, security completeness, or absence of vulnerabilities;
- producer delivery certainty, idempotence, transaction fencing or isolation,
  consumer offset safety, rebalance correctness, cancellation reconciliation,
  shutdown, fault, restart, rolling-version, teardown, or residue behavior;
- performance, throughput, latency, memory, resource bounds, reliability,
  broad workspace health, release readiness, migration readiness, or absence of
  defects;
- completeness or absence of external/public/private downstream consumers, or
  freshness beyond each frozen child revision;
- closure of any routed K1-K15 or standalone owner, or permission to treat
  planned, local, mock, proof-only, compile-only, silent-skip, or untracked work
  as terminal evidence; or
- permission to remove or delete `rdkafka`, `librdkafka`, the `kafka` feature,
  a public API, behavior, source file, fixture, artifact, capability, or any
  other project data.

It also grants no production-wiring or oracle-retirement authority. The
machine receipt records `migration_eligible=false`,
`production_wiring_allowed=false`, `oracle_retirement_allowed=false`, and
`cutover_allowed=false`.

Any proposed migration or cutover remains fail-closed at `KEEP_INCUMBENT` until
the applicable later owners produce their independently admitted terminal
evidence and K15 records a separately authorized decision.

<!-- END KAFKA K0.5 BASELINE DISPOSITION -->
