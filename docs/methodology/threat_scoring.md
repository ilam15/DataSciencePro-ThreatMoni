# ThreatMoni Threat Scoring Methodology

## Theoretical Formulation

ThreatMoni models threat severity and priority using a multi-factor mathematical formulation combining source credibility, entity density, intelligence quality, and risk vectors.

### 1. Source Credibility Score (SCS)
$$\text{SCS} = \frac{R + U + C + A}{4} \times 100$$
- **Reliability ($R$):** Forum & community validation sentiment.
- **Update Frequency ($U$):** Information granularity & detail density.
- **Consistency ($C$):** Consensus matching across threat categories, predictions, and topic labels.
- **Authority ($A$):** Threat Actor / Source reputation proxy (known APT groups vs. unknown actors).

### 2. Threat Frequency Score (TFS)
$$\text{TFS} = \frac{N_t}{N}$$
- $N_t$: Number of OSINT records belonging to threat entity $t$.
- $N$: Total collected OSINT baseline records ($N = 1,100$).

### 3. Intelligence Quality (IQ)
$$\text{IQ} = \left(0.4 \times \text{Completeness} + 0.3 \times \text{IOC Presence} + 0.3 \times \text{Text Detail}\right) \times 100$$

### 4. Threat Confidence Score (TCS)
$$\text{TCS} = \alpha(\text{SCS}) + \beta(\text{IQ})$$
- Configured default weights: $\alpha = 0.5, \beta = 0.5$ (defined in `configs/scoring.yaml`).

### 5. Threat Risk Score (TRS)
$$\text{TRS} = \sum (W_i \times F_i)$$
- **Features ($F_i$):** Severity score ($30\%$), TFS ($25\%$), Risk prediction ($20\%$), IOC count ($15\%$), Forum sentiment ($10\%$).

### 6. Threat Priority Index (TPI)
$$\text{TPI} = \frac{\text{TRS} \times \text{TCS}}{100}$$

## Priority Levels
- **0 – 25:** Low Priority
- **26 – 50:** Medium Priority
- **51 – 75:** High Priority
- **76 – 100:** Critical Priority
