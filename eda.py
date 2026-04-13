"""
Phase 1 — Dataset Exploration & EDA
Phishing Detection System
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
DATA_PATH = Path("data/phishing.csv")
OUT_PATH  = Path("outputs")
OUT_PATH.mkdir(exist_ok=True)

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor":   "white",
    "axes.spines.top":  False,
    "axes.spines.right":False,
    "font.family":      "DejaVu Sans",
    "font.size":        11,
})

PHISHING_COLOR   = "#E8593C"
LEGIT_COLOR      = "#1D9E75"
NEUTRAL_COLOR    = "#7F77DD"

# ── 1. Load & Basic Info ───────────────────────────────────────────────────
print("=" * 60)
print("  PHISHING DETECTION — DATASET EXPLORATION")
print("=" * 60)

df = pd.read_csv(DATA_PATH)

# Support common target column variants used in phishing datasets.
target_candidates = ["Result", "class", "Class", "label", "Label"]
target_col = next((c for c in target_candidates if c in df.columns), None)
if target_col is None:
    raise ValueError(
        f"Could not find target column. Expected one of: {target_candidates}"
    )

print(f"\n[1] SHAPE")
print(f"    Rows    : {df.shape[0]:,}")
print(f"    Columns : {df.shape[1]}")

print(f"\n[2] COLUMN NAMES")
features = [c for c in df.columns if c != target_col]
for i, col in enumerate(features, 1):
    print(f"    {i:2}. {col}")

print(f"\n[3] DATA TYPES")
print(df.dtypes.value_counts().to_string())

print(f"\n[4] MISSING VALUES")
missing = df.isnull().sum()
if missing.sum() == 0:
    print("    No missing values — dataset is complete.")
else:
    print(missing[missing > 0])

print(f"\n[5] UNIQUE VALUES PER COLUMN (UCI uses -1, 0, 1)")
for col in df.columns:
    print(f"    {col:<35} {sorted(df[col].unique())}")

# ── 2. Class Distribution ──────────────────────────────────────────────────
# UCI convention: Result = 1 → Legitimate, Result = -1 → Phishing
label_map   = {1: "Legitimate", -1: "Phishing"}
df["Label"] = df[target_col].map(label_map)
counts      = df["Label"].value_counts()
pct         = df["Label"].value_counts(normalize=True) * 100

print(f"\n[6] CLASS DISTRIBUTION")
for label, cnt in counts.items():
    print(f"    {label:<12} : {cnt:,}  ({pct[label]:.1f}%)")

# ── 3. Feature Value Distributions ────────────────────────────────────────
print(f"\n[7] FEATURE VALUE COUNTS (% of rows)")
val_pcts = {}
for col in features:
    vc = df[col].value_counts(normalize=True) * 100
    val_pcts[col] = {v: round(vc.get(v, 0), 1) for v in [-1, 0, 1]}

# ── 4. Correlation with Target ─────────────────────────────────────────────
df_num = df[features + [target_col]]
corr_target = df_num.corr()[target_col].drop(target_col).sort_values()

print(f"\n[8] TOP 10 FEATURES CORRELATED WITH TARGET")
print("    (positive = more correlated with legitimate)")
for feat, val in corr_target.abs().sort_values(ascending=False).head(10).items():
    print(f"    {feat:<35} {val:.4f}")

# ═══════════════════════════════════════════════════════════════════════════
# PLOTS
# ═══════════════════════════════════════════════════════════════════════════

# ── Plot 1: Class Distribution ─────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(11, 5))
fig.suptitle("Class Distribution", fontsize=14, fontweight="bold", y=1.01)

colors = [LEGIT_COLOR, PHISHING_COLOR]
bars = axes[0].bar(counts.index, counts.values, color=colors, width=0.5, edgecolor="white")
axes[0].set_title("Count")
axes[0].set_ylabel("Number of samples")
for bar, val in zip(bars, counts.values):
    axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 80,
                 f"{val:,}", ha="center", fontsize=11, fontweight="bold")

wedges, texts, autotexts = axes[1].pie(
    counts.values, labels=counts.index, colors=colors,
    autopct="%1.1f%%", startangle=90,
    wedgeprops={"edgecolor": "white", "linewidth": 2}
)
for at in autotexts:
    at.set_fontsize(12)
    at.set_fontweight("bold")
axes[1].set_title("Proportion")

plt.tight_layout()
plt.savefig(OUT_PATH / "01_class_distribution.png", dpi=150, bbox_inches="tight")
plt.close()
print("\n    Saved: 01_class_distribution.png")

# ── Plot 2: Feature Correlation with Target ────────────────────────────────
fig, ax = plt.subplots(figsize=(10, 9))
colors_bar = [LEGIT_COLOR if v > 0 else PHISHING_COLOR for v in corr_target.values]
bars = ax.barh(corr_target.index, corr_target.values, color=colors_bar, edgecolor="white")
ax.axvline(0, color="gray", linewidth=0.8, linestyle="--")
ax.set_title("Feature Correlation with Target\n(green = correlated with legitimate, red = correlated with phishing)",
             fontsize=12, fontweight="bold")
ax.set_xlabel("Pearson Correlation")
plt.tight_layout()
plt.savefig(OUT_PATH / "02_feature_correlation.png", dpi=150, bbox_inches="tight")
plt.close()
print("    Saved: 02_feature_correlation.png")

# ── Plot 3: Correlation Heatmap (all features) ─────────────────────────────
fig, ax = plt.subplots(figsize=(14, 12))
corr_matrix = df_num.corr()
mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
sns.heatmap(
    corr_matrix, mask=mask, annot=False, fmt=".2f",
    cmap="RdYlGn", center=0, linewidths=0.3,
    cbar_kws={"shrink": 0.8}, ax=ax
)
ax.set_title("Full Feature Correlation Matrix", fontsize=13, fontweight="bold", pad=15)
plt.tight_layout()
plt.savefig(OUT_PATH / "03_correlation_heatmap.png", dpi=150, bbox_inches="tight")
plt.close()
print("    Saved: 03_correlation_heatmap.png")

# ── Plot 4: Feature Value Distribution (stacked bars) ─────────────────────
n_feat = len(features)
fig, ax = plt.subplots(figsize=(12, 9))

y_pos    = np.arange(n_feat)
vals_n1  = [val_pcts[f][-1] for f in features]
vals_0   = [val_pcts[f][0]  for f in features]
vals_p1  = [val_pcts[f][1]  for f in features]

b1 = ax.barh(y_pos, vals_n1, color=PHISHING_COLOR, label="-1 (phishing indicator)", edgecolor="white")
b2 = ax.barh(y_pos, vals_0,  left=vals_n1, color="#AAAAAA", label="0 (neutral)", edgecolor="white")
b3 = ax.barh(y_pos, vals_p1, left=[a+b for a,b in zip(vals_n1, vals_0)],
             color=LEGIT_COLOR, label="1 (legit indicator)", edgecolor="white")

ax.set_yticks(y_pos)
ax.set_yticklabels(features, fontsize=9)
ax.set_xlabel("Percentage of samples (%)")
ax.set_title("Feature Value Distribution\n(UCI encoding: -1 = phishing, 0 = neutral, 1 = legitimate)",
             fontsize=12, fontweight="bold")
ax.legend(loc="lower right", fontsize=9)
ax.set_xlim(0, 100)
plt.tight_layout()
plt.savefig(OUT_PATH / "04_feature_value_distribution.png", dpi=150, bbox_inches="tight")
plt.close()
print("    Saved: 04_feature_value_distribution.png")

# ── Plot 5: Top features by class separation ──────────────────────────────
top_features = corr_target.abs().sort_values(ascending=False).head(8).index.tolist()
fig, axes = plt.subplots(2, 4, figsize=(14, 7))
fig.suptitle("Top 8 Discriminative Features — Value Distribution by Class",
             fontsize=13, fontweight="bold")

for ax, feat in zip(axes.flatten(), top_features):
    phish_vals = df[df["Label"] == "Phishing"][feat].value_counts(normalize=True) * 100
    legit_vals = df[df["Label"] == "Legitimate"][feat].value_counts(normalize=True) * 100

    x = np.array([-1, 0, 1])
    ph = [phish_vals.get(v, 0) for v in x]
    lg = [legit_vals.get(v, 0) for v in x]

    w = 0.35
    ax.bar(x - w/2, ph, width=w, color=PHISHING_COLOR, label="Phishing", alpha=0.9)
    ax.bar(x + w/2, lg, width=w, color=LEGIT_COLOR,    label="Legit",    alpha=0.9)
    ax.set_title(feat, fontsize=8, fontweight="bold")
    ax.set_xticks([-1, 0, 1])
    ax.set_xticklabels(["-1", "0", "1"], fontsize=8)
    ax.set_ylabel("% samples", fontsize=8)

axes[0][0].legend(fontsize=7, loc="upper right")
plt.tight_layout()
plt.savefig(OUT_PATH / "05_top_features_by_class.png", dpi=150, bbox_inches="tight")
plt.close()
print("    Saved: 05_top_features_by_class.png")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  EDA SUMMARY")
print("=" * 60)
print(f"  Total samples   : {len(df):,}")
print(f"  Features        : {len(features)}")
print(f"  Missing values  : 0")
print(f"  Class balance   : {pct['Legitimate']:.1f}% legitimate / {pct['Phishing']:.1f}% phishing")
imbalance = abs(pct['Legitimate'] - pct['Phishing'])
if imbalance < 10:
    print(f"  Balance status  : GOOD — no resampling needed (diff = {imbalance:.1f}%)")
else:
    print(f"  Balance status  : CONSIDER SMOTE or class_weight (diff = {imbalance:.1f}%)")

top3 = corr_target.abs().sort_values(ascending=False).head(3)
print(f"\n  Most predictive features:")
for feat, val in top3.items():
    print(f"    → {feat} (r={val:.3f})")

print(f"\n  All plots saved to: outputs/")
print("=" * 60)
print("\n  Next step: Phase 2 — Feature extraction pipeline")
print("=" * 60)
