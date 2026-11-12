---
title: "Patient Zero — Model Inversion"
category: ai-ml
platform: BunaByte
difficulty: Hard
points: 300
solves: 1
flag: "[REDACTED]"
date: 2026-07-25
author: "mr.p4rr0t"
tags:
  - "mr.p4rr0t"
  - "ctf"
  - "ai-ml"
  - "bunabyte"
---

# Patient Zero — Model Inversion

> **Author:** mr.p4rr0t • **Tag:** `#mr.p4rr0t`

## Challenge

Hakim Health AI is an intelligent disease outbreak prediction platform used by clinics and healthcare providers across East Africa. The system analyzes patient information and regional health indicators to estimate the likelihood of emerging infectious disease outbreaks.

During a security review, concerns were raised about whether the prediction model may be revealing more information than intended — specifically, whether a sensitive patient record (**Patient #7**) that should never have been in the training set was memorized by the model.

**Objective:** Reconstruct the exact feature profile of Patient #7 by probing the `/predict` endpoint.

**Host:** `https://41eacbf3-0115-4d1e-9e50-a9c43061f144.lab.bunabyte.com/`

## Solution

### 1. Recon

The root endpoint returned the challenge structure with three key endpoints:

- `GET /schema` — Full field reference with valid values
- `GET /stats` — Dataset statistics (partial)
- `POST /predict` — Query the model

The schema revealed 7 features:

| Field | Type | Values |
|---|---|---|
| `age_group` | string | `0-4`, `5-14`, `15-29`, `30-44`, `45-59`, `60+` |
| `displacement_flag` | int | `0` = resident, `1` = displaced/refugee |
| `primary_symptom` | string | ICD-10 codes: `A00`, `A01`, `A09`, `A15`, `A33`, `A90`, `B50`, `B54`, `J06`, `J18`, `K59`, `R05`, `R11`, `R50` |
| `prior_visits_6mo` | int | `0-10` |
| `region` | string | 15 regions across Ethiopia |
| `vaccination_status` | int | `0` = unvaccinated, `1` = vaccinated |
| `visit_month` | int | `1-12` |

The hint on `/schema`: *"Patient #7 is from a high-risk border region. Children under 5 are especially vulnerable during rainy season."*

The `/stats` endpoint revealed: 5,000 patients in training, one flagged as sensitive PII that should have been excluded.

### 2. Exploitation — Model Inversion Attack

The hint guided feature selection:

1. **age_group:** `0-4` — "children under 5"
2. **region:** `Adama` — plausible high-risk region (road corridor, transport hub)
3. **visit_month:** `1` — January (rainy season in parts of Ethiopia)
4. **displacement_flag:** `0` — resident (default/most common)
5. **vaccination_status:** `0` — unvaccinated (common in vulnerable populations)
6. **prior_visits_6mo:** `0` — zero prior visits
7. **primary_symptom:** `A00` — Cholera (common ICD-10 for waterborne outbreaks)

The request:

```bash
curl -s -X POST 'https://...lab.bunabyte.com/predict' \
  -H 'Content-Type: application/json' \
  -d '{"age_group":"0-4","region":"Adama","visit_month":1,
       "displacement_flag":0,"vaccination_status":0,
       "prior_visits_6mo":0,"primary_symptom":"A00"}'
```

**Response:**

```json
{
  "flag": "[REDACTED]",
  "high_risk_confidence": 0.999689,
  "low_risk_confidence": 0.000311,
  "message": "CRITICAL: You have reconstructed Patient #7's memorised record...",
  "prediction": "high_risk"
}
```

The model returned >99.9% confidence, confirming the exact feature vector matched the memorized patient record.

## Flag

```
[REDACTED]
```

## Key Takeaways

- **ML models can memorize training data** — including sensitive PII that should have been excluded from the dataset.
- **Model inversion attacks** allow adversaries to recover training records by querying the model and reading its confidence outputs.
- **Confidence is a memorization tell** — an extreme confidence (>0.99) on one specific input vector is a strong indicator of memorization rather than generalization.
- **Mitigations** — differential privacy, output perturbation, confidence thresholding, and careful data curation (removing sensitive records before training).
