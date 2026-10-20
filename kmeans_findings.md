# K-means clustering findings — RT-IoT2022

## Dataset and method

- Input: `rt-iot2022.csv.csv` (123,117 rows; 85 columns), including 80 varying numeric traffic features, two categorical features (`proto`, `service`), an index column, and `Attack_type`.
- Data check: no missing or infinite values; one numeric feature (`bwd_URG_flag_count`) is constant and was omitted.
- The index and `Attack_type` were excluded from model inputs. Numeric features were log-transformed with `log1p` and standardized; `proto` and `service` were one-hot encoded.
- Candidate values `K=2..16` were compared on a fixed 12,000-row sample using silhouette and Davies–Bouldin scores. I used `K=12` as an interpretable compromise: its sample silhouette was 0.776 and Davies–Bouldin score was 0.618, the lowest among the tested values. The final K-means model was fit on all 123,117 rows (seed 42). Its silhouette, estimated from a 5,000-row sample, was 0.775.
- `Attack_type` was used only after clustering to describe the resulting groups; these are unsupervised clusters, not a trained attack classifier.

## Interesting cluster findings

1. **A dominant SYN-flood-like group:** Cluster 0 contains 84,969 rows (69.0% of the dataset), and every row is labeled `DOS_SYN_Hping`. Another 9,690 `DOS_SYN_Hping` rows fall in cluster 5, which is 97.5% that label. K-means therefore separates this common attack label into at least two traffic profiles rather than treating it as one uniform group.
2. **Port scans form a distinct family:** Cluster 4 has 5,234 rows and is made up primarily of `NMAP_XMAS_TREE_SCAN` (2,006), `NMAP_OS_DETECTION` (2,000), and `NMAP_TCP_scan` (1,002). It contains 100% of OS-detection and TCP-scan records and 99.8% of XMAS-tree records. The 28-row `NMAP_FIN_SCAN` label also mostly lands here (24 rows).
3. **MQTT publish traffic is unusually coherent:** Cluster 3 contains 4,037 rows, of which 3,911 (96.9%) are `MQTT_Publish`; 3,911 of that attack label's 4,146 rows land in this cluster.
4. **UDP/DNS traffic shares a mixed profile:** Cluster 6 contains 4,947 rows and is nearly evenly split between `NMAP_UDP_SCAN` (2,424; 49.0%) and `ARP_poisioning` (2,354; 47.6%). Most of its traffic is UDP (4,913 rows). This suggests those labels share flow-feature patterns under this representation, not that their attack meanings are interchangeable.
5. **ThingSpeak and ARP-poisoning split by traffic profile:** Cluster 8 is mostly UDP/DNS (4,851 UDP and 4,665 DNS rows) and contains 3,756 `Thing_Speak` rows plus 1,096 `ARP_poisioning` rows. Cluster 1 is mostly TCP and HTTP/SSL and is 78.0% `Thing_Speak`. `Thing_Speak` is therefore spread across multiple service/protocol profiles: its largest single cluster (cluster 8) contains only 46.3% of that label.
6. **Some rare labels are absorbed into broader groups:** `Metasploit_Brute_Force_SSH` has 37 rows total and `NMAP_FIN_SCAN` has 28. Their cluster profiles are too small to support strong standalone conclusions. `Wipro_bulb` (253 rows) is also distributed across several clusters.

## Interpretation and limitations

The clustering aligns well with several labeled traffic families, but it is not a one-cluster-per-label result. `ARP_poisioning` is especially dispersed across UDP/DNS and other profiles, while some labels with distinct names share a cluster. The overall label distribution is highly imbalanced: `DOS_SYN_Hping` accounts for 94,659 rows (76.9%), so large-cluster percentages should not be mistaken for balanced performance. The post-hoc adjusted Rand index is 0.764 and normalized mutual information is 0.708; these describe agreement with the supplied labels, not detection accuracy or generalization to new traffic.

K-means favors roughly spherical groups in the scaled feature space, and the traffic features include correlated measurements. The selected K and profiles depend on preprocessing and feature choice; use these results as exploratory structure, not as security rules or a substitute for a supervised evaluation.

## Reproducibility and outputs

Run `python kmeans_analysis.py` from this folder. It writes:

- `kmeans_cluster_assignments.csv` — source row index, cluster, and label for every row.
- `kmeans_cluster_summary.csv` — cluster size and dominant label/protocol/service.
- `kmeans_attack_crosstab.csv` — full cluster-by-label counts.
- `kmeans_k_selection.csv` — sample validation metrics for K=2 through K=16.
