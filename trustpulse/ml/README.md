# TRUSTPULSE ML Toolkit

Numeric core of the trust model. **This library produces evidence and scores only.
It never returns an authorization decision.** All enforcement goes through the
server-side Policy Enforcement Point in `backend/app/services/enforcement/`.

Installable as `trustpulse-ml`, importable as `trustpulse_ml`:

```python
from trustpulse_ml.trust_fusion.fusion import fuse_factors
from trustpulse_ml.anomaly_detection.detector import StatisticalAnomalyDetector
```

| Module | Responsibility |
|---|---|
| `feature_extraction/` | Canonical, privacy-minimized feature schema + normalization of SDK-derived features |
| `baseline/` | Trusted Core (slow, gated) and Adaptive Shadow (fast, quarantined) baselines |
| `anomaly_detection/` | Robust z-score / Mahalanobis / cosine statistical detector + optional IsolationForest |
| `trust_fusion/` | Weighted fusion of the six TCI factors |
| `evaluation/` | Offline precision / recall / FPR / detection-latency reporting |

## Privacy rules enforced here

1. Only **derived aggregate features** (means, standard deviations, rates) are accepted.
2. Typed characters are never accepted: `extract_feature_vector` has no code path for
   keystroke text, and raises on any key that looks like raw text.
3. Nothing produced by this library contains user identity or raw recordings.
