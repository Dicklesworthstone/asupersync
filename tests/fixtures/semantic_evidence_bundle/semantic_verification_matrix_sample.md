# Semantic Verification Matrix (Fixture)

## 4. Verification Matrix

### 4.1 Cancellation Domain (#1-3)

| # | Rule ID | Tier | UT | PT | OC | E2E | LOG | DOC | CI | Status |
|---|---------|:----:|:--:|:--:|:--:|:---:|:---:|:---:|:--:|:------:|
| 1 | `inv.cancel.idempotence` | HIGH | Y | - | Y | - | - | Y | - | UT+OC+DOC |
| 2 | `rule.cancel.request` | MED | Y | - | Y | - | - | - | - | UT+OC |
| 3 | `def.cancel.reason_kinds` | LOW | Y | - | - | - | - | - | - | UT |

### 4.2 Determinism Domain (#47)

| # | Rule ID | Tier | UT | PT | OC | E2E | LOG | DOC | CI | Status |
|---|---------|:----:|:--:|:--:|:--:|:---:|:---:|:---:|:--:|:------:|
| 47 | `def.determinism.seed_equivalence` | HIGH | Y | - | Y | Y | - | - | - | UT+OC+E2E |
