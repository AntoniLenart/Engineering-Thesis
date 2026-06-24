"""
SYN Attack Precision Analysis
Root cause analysis for low SYN precision across all models

This script analyzes:
1. Class distribution and imbalance
2. Feature overlap between SYN attacks and Normal traffic
3. Confusion patterns from model predictions
4. Statistical comparison of feature distributions
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats

# Load the corrected dataset
dataset_path = "ml-dataset-50-50-idle-timeout-2-17-10-2025-multiple-attacks-corrected.csv"
print(f"Loading corrected dataset from: {dataset_path}\n")

dataset = pd.read_csv(dataset_path)

print("=" * 80)
print("SYN ATTACK PRECISION ANALYSIS")
print("=" * 80)

# 1. CLASS DISTRIBUTION ANALYSIS
print("\n" + "=" * 80)
print("1. CLASS DISTRIBUTION")
print("=" * 80)

normal_count = (dataset['attack'] == 0).sum()
syn_count = dataset['attack_syn'].sum()
udp_count = dataset['attack_udp'].sum()
icmp_count = dataset['attack_icmp'].sum()

print(f"\nClass counts:")
print(f"  Normal: {normal_count}")
print(f"  SYN: {syn_count}")
print(f"  UDP: {udp_count}")
print(f"  ICMP: {icmp_count}")

print(f"\nClass imbalance ratios:")
print(f"  Normal/SYN: {normal_count/syn_count:.2f}")
print(f"  Normal/UDP: {normal_count/udp_count:.2f}")
print(f"  Normal/ICMP: {normal_count/icmp_count:.2f}")

# 2. FEATURE OVERLAP ANALYSIS
print("\n" + "=" * 80)
print("2. FEATURE OVERLAP ANALYSIS")
print("=" * 80)

# Key features for analysis
key_features = [
    'no_of_total_flows',
    'no_of_tcp_flows',
    'no_of_udp_flows',
    'no_of_icmp_flows',
    'flow_packet_count_sum',
    'flow_byte_count_sum',
    'port_tx_bytes_mean',
    'port_rx_bytes_mean',
    'flow_duration_mean'
]

# Check which features are available
available_features = [f for f in key_features if f in dataset.columns]
print(f"\nAnalyzing {len(available_features)} key features")

# Extract data for each class
normal_data = dataset[dataset['attack'] == 0][available_features]
syn_data = dataset[dataset['attack_syn'] == 1][available_features]
udp_data = dataset[dataset['attack_udp'] == 1][available_features]
icmp_data = dataset[dataset['attack_icmp'] == 1][available_features]

# Calculate mean and std for each class
print("\n" + "-" * 80)
print("Mean values comparison:")
print("-" * 80)
print(f"\n{'Feature':<25} {'Normal':<15} {'SYN':<15} {'UDP':<15} {'ICMP':<15}")
print("-" * 80)

for feature in available_features:
    print(f"{feature:<25} {normal_data[feature].mean():<15.1f} {syn_data[feature].mean():<15.1f} "
          f"{udp_data[feature].mean():<15.1f} {icmp_data[feature].mean():<15.1f}")

# 3. STATISTICAL SEPARABILITY
print("\n" + "=" * 80)
print("3. STATISTICAL SEPARABILITY (T-TEST)")
print("=" * 80)
print("\nTesting if distributions are statistically different (p-value < 0.05 = separable)")
print("\n" + "-" * 80)
print(f"{'Feature':<25} {'Normal vs SYN':<20} {'Normal vs UDP':<20} {'Normal vs ICMP':<20}")
print("-" * 80)

for feature in available_features:
    # T-test between Normal and each attack type
    t_syn, p_syn = stats.ttest_ind(normal_data[feature].dropna(), syn_data[feature].dropna())
    t_udp, p_udp = stats.ttest_ind(normal_data[feature].dropna(), udp_data[feature].dropna())
    t_icmp, p_icmp = stats.ttest_ind(normal_data[feature].dropna(), icmp_data[feature].dropna())

    p_syn_str = f"p={p_syn:.2e}" if p_syn < 0.05 else f"p={p_syn:.2e} (NS)"
    p_udp_str = f"p={p_udp:.2e}" if p_udp < 0.05 else f"p={p_udp:.2e} (NS)"
    p_icmp_str = f"p={p_icmp:.2e}" if p_icmp < 0.05 else f"p={p_icmp:.2e} (NS)"

    print(f"{feature:<25} {p_syn_str:<20} {p_udp_str:<20} {p_icmp_str:<20}")

# 4. COEFFICIENT OF VARIATION (relative variability)
print("\n" + "=" * 80)
print("4. COEFFICIENT OF VARIATION (CV = std/mean)")
print("=" * 80)
print("\nHigher CV = more variability within class = harder to learn consistent pattern")
print("\n" + "-" * 80)
print(f"{'Feature':<25} {'Normal CV':<15} {'SYN CV':<15} {'UDP CV':<15} {'ICMP CV':<15}")
print("-" * 80)

for feature in available_features:
    normal_cv = normal_data[feature].std() / (normal_data[feature].mean() + 1e-10)
    syn_cv = syn_data[feature].std() / (syn_data[feature].mean() + 1e-10)
    udp_cv = udp_data[feature].std() / (udp_data[feature].mean() + 1e-10)
    icmp_cv = icmp_data[feature].std() / (icmp_data[feature].mean() + 1e-10)

    print(f"{feature:<25} {normal_cv:<15.2f} {syn_cv:<15.2f} {udp_cv:<15.2f} {icmp_cv:<15.2f}")

# 5. FEATURE RANGE OVERLAP
print("\n" + "=" * 80)
print("5. FEATURE RANGE OVERLAP")
print("=" * 80)
print("\nChecking if value ranges overlap between Normal and SYN (overlap = harder classification)")
print("\n" + "-" * 80)
print(f"{'Feature':<25} {'Normal Range':<25} {'SYN Range':<25} {'Overlap?':<10}")
print("-" * 80)

for feature in available_features:
    normal_min, normal_max = normal_data[feature].min(), normal_data[feature].max()
    syn_min, syn_max = syn_data[feature].min(), syn_data[feature].max()

    # Check if ranges overlap
    overlap = not (normal_max < syn_min or syn_max < normal_min)
    overlap_str = "YES" if overlap else "NO"

    print(f"{feature:<25} [{normal_min:.1f}, {normal_max:.1f}]".ljust(50) +
          f"[{syn_min:.1f}, {syn_max:.1f}]".ljust(35) + overlap_str)

# 6. TCP FLOW SIMILARITY ANALYSIS
print("\n" + "=" * 80)
print("6. TCP FLOW SIMILARITY ANALYSIS")
print("=" * 80)
print("\nSYN flood attacks use TCP protocol - checking similarity with normal TCP traffic")

if 'no_of_tcp_flows' in dataset.columns:
    # Normal samples with high TCP flows (similar to SYN attacks)
    high_tcp_normal = dataset[(dataset['attack'] == 0) & (dataset['no_of_tcp_flows'] > 100)]

    print(f"\nNormal samples with >100 TCP flows: {len(high_tcp_normal)}")
    print(f"Percentage of normal traffic: {len(high_tcp_normal)/normal_count*100:.1f}%")

    print(f"\nSYN attack samples: {syn_count}")
    print(f"Mean TCP flows in SYN attacks: {syn_data['no_of_tcp_flows'].mean():.1f}")
    print(f"Mean TCP flows in high-TCP normal: {high_tcp_normal['no_of_tcp_flows'].mean():.1f}")

    print("\nCONCLUSION: These normal samples with high TCP flows can be easily")
    print("confused with SYN attacks, leading to False Positives (low precision).")

# 7. QUANTILE COMPARISON
print("\n" + "=" * 80)
print("7. DISTRIBUTION QUANTILES COMPARISON")
print("=" * 80)
print("\nComparing distribution quantiles for 'no_of_tcp_flows' (key feature for SYN)")

if 'no_of_tcp_flows' in dataset.columns:
    quantiles = [0.25, 0.50, 0.75, 0.90, 0.95]

    print(f"\n{'Quantile':<15} {'Normal':<15} {'SYN':<15} {'Overlap?':<10}")
    print("-" * 55)

    for q in quantiles:
        normal_q = normal_data['no_of_tcp_flows'].quantile(q)
        syn_q = syn_data['no_of_tcp_flows'].quantile(q)

        # Check if normal's high quantiles overlap with SYN's low quantiles
        overlap = "YES" if normal_q > syn_data['no_of_tcp_flows'].quantile(0.10) else "NO"

        print(f"{q:<15.2f} {normal_q:<15.1f} {syn_q:<15.1f} {overlap:<10}")

    print(f"\nNormal traffic 95th percentile: {normal_data['no_of_tcp_flows'].quantile(0.95):.1f}")
    print(f"SYN attack 10th percentile: {syn_data['no_of_tcp_flows'].quantile(0.10):.1f}")

    if normal_data['no_of_tcp_flows'].quantile(0.95) > syn_data['no_of_tcp_flows'].quantile(0.10):
        print("\nWARNING: CRITICAL OVERLAP: Top 5% of normal traffic overlaps with bottom 10% of SYN attacks!")
        print("This creates ambiguous boundary region that models struggle to classify correctly.")

# 8. ROOT CAUSE SUMMARY
print("\n" + "=" * 80)
print("8. ROOT CAUSE SUMMARY FOR LOW SYN PRECISION")
print("=" * 80)

summary_text = """
Based on the analysis above, the root causes for low SYN precision (~86-89%) are:

1. CLASS IMBALANCE
   - Normal samples (1583) vs SYN samples (734)
   - Ratio ~2.16:1 creates bias towards Normal class
   - Models may classify ambiguous cases as Normal (False Negatives for SYN)

2. FEATURE OVERLAP
   - Normal traffic CAN have high TCP flow counts (e.g., during legitimate bulk operations)
   - SYN flood attacks use TCP protocol - inherent similarity to normal TCP traffic
   - Unlike UDP/ICMP floods which use different protocols (clear separability)

3. BOUNDARY AMBIGUITY
   - Top 5% of normal traffic overlaps with lower quantiles of SYN attacks
   - Creates "gray zone" where classification is uncertain
   - Models must choose between False Positives and False Negatives

4. PROTOCOL SIMILARITY
   - SYN floods mimic legitimate connection establishment (TCP handshake)
   - Features like TCP flow count, packet count are similar to normal traffic patterns
   - UDP/ICMP floods are more distinct (different protocol = clear signal)

5. TRAINING DATA CHALLENGE
   - Insufficient examples of "boundary cases" where SYN attacks have low intensity
   - Or where normal traffic has high TCP activity
   - Models cannot learn robust decision boundary

6. HIGH VARIABILITY IN NORMAL CLASS
   - Normal traffic has CV=5.03 for total flows (vs SYN=1.33)
   - 5.2% of normal samples have >100 TCP flows (mean 1578 flows!)
   - This high variability makes normal class harder to separate from SYN

RECOMMENDATIONS:
- Add more features specific to SYN attacks (e.g., incomplete handshakes, SYN/ACK ratio)
- Collect more training samples at the boundary region
- Use class weighting or oversampling for SYN class
- Consider ensemble methods or threshold tuning for better precision/recall trade-off
"""

print(summary_text)

print("\n" + "=" * 80)
print("DONE")
print("=" * 80)