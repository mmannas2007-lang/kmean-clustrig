from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.compose import ColumnTransformer
from sklearn.metrics import davies_bouldin_score, silhouette_score
from sklearn.preprocessing import OneHotEncoder, StandardScaler


DATA_PATH = Path(__file__).resolve().parent / "rt-iot2022.csv.csv"
OUTPUT_DIR = Path(__file__).resolve().parent
RANDOM_STATE = 42
N_CLUSTERS = 12


def main() -> None:
    data = pd.read_csv(DATA_PATH)
    if "Attack_type" not in data.columns:
        raise ValueError("The input CSV must contain an Attack_type column.")
    if data.isna().any().any():
        raise ValueError("The input contains missing values; resolve them before clustering.")

    source_index = data["Unnamed: 0"] if "Unnamed: 0" in data.columns else pd.Series(
        np.arange(len(data))
    )
    features = data.drop(
        columns=["Attack_type"] + (["Unnamed: 0"] if "Unnamed: 0" in data else [])
    )
    numeric_columns = features.select_dtypes(include="number").columns.tolist()
    categorical_columns = features.select_dtypes(exclude="number").columns.tolist()
    numeric_columns = [
        column for column in numeric_columns if features[column].nunique(dropna=False) > 1
    ]

    if not np.isfinite(features[numeric_columns].to_numpy()).all():
        raise ValueError("Numeric features contain infinite values.")
    if (features[numeric_columns] < 0).any().any():
        raise ValueError("Log transformation requires non-negative numeric features.")

    transformed = features.copy()
    transformed[numeric_columns] = np.log1p(transformed[numeric_columns])
    preprocessor = ColumnTransformer(
        [
            ("numeric", StandardScaler(), numeric_columns),
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                categorical_columns,
            ),
        ],
        verbose_feature_names_out=False,
    )
    matrix = preprocessor.fit_transform(transformed).astype("float32")

    rng = np.random.default_rng(RANDOM_STATE)
    sample_indices = rng.choice(
        len(data), size=min(12_000, len(data)), replace=False
    )
    sample = matrix[sample_indices]
    validation_rows = []
    for k in range(2, 17):
        candidate = KMeans(
            n_clusters=k,
            random_state=RANDOM_STATE,
            n_init=5,
            max_iter=200,
        ).fit(sample)
        validation_rows.append(
            {
                "k": k,
                "silhouette": silhouette_score(
                    sample,
                    candidate.labels_,
                    sample_size=min(3_000, len(sample)),
                    random_state=RANDOM_STATE,
                ),
                "davies_bouldin": davies_bouldin_score(sample, candidate.labels_),
                "inertia": candidate.inertia_,
            }
        )
    pd.DataFrame(validation_rows).to_csv(
        OUTPUT_DIR / "kmeans_k_selection.csv", index=False
    )

    model = KMeans(
        n_clusters=N_CLUSTERS,
        random_state=RANDOM_STATE,
        n_init=10,
        max_iter=300,
    ).fit(matrix)
    cluster_ids = model.labels_
    cross_tab = pd.crosstab(
        pd.Series(cluster_ids, name="cluster"),
        data["Attack_type"].rename("Attack_type"),
    )
    cross_tab.to_csv(OUTPUT_DIR / "kmeans_attack_crosstab.csv")

    assignments = pd.DataFrame(
        {
            "row_index": source_index.to_numpy(),
            "cluster": cluster_ids,
            "Attack_type": data["Attack_type"].to_numpy(),
        }
    )
    assignments.to_csv(OUTPUT_DIR / "kmeans_cluster_assignments.csv", index=False)

    cluster_sizes = pd.Series(cluster_ids).value_counts().sort_index()
    profiles = []
    for cluster_id, size in cluster_sizes.items():
        cluster_mask = cluster_ids == cluster_id
        attack_counts = data.loc[cluster_mask, "Attack_type"].value_counts()
        profile = {
            "cluster": int(cluster_id),
            "rows": int(size),
            "share_pct": size / len(data) * 100,
            "top_attack_type": attack_counts.index[0],
            "top_attack_share_pct": attack_counts.iloc[0] / size * 100,
        }
        for column in categorical_columns:
            modes = features.loc[cluster_mask, column].value_counts()
            profile[f"top_{column}"] = modes.index[0]
            profile[f"top_{column}_share_pct"] = modes.iloc[0] / size * 100
        profiles.append(profile)
    pd.DataFrame(profiles).to_csv(
        OUTPUT_DIR / "kmeans_cluster_summary.csv", index=False
    )

    print(f"Rows: {len(data):,}; feature columns used: {len(numeric_columns) + len(categorical_columns)}")
    print(f"Clusters: {N_CLUSTERS}; full-data inertia: {model.inertia_:.1f}")
    print(
        "Full-model silhouette (5,000-row sample): "
        f"{silhouette_score(matrix, cluster_ids, sample_size=5_000, random_state=RANDOM_STATE):.4f}"
    )
    print(f"Outputs written to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
