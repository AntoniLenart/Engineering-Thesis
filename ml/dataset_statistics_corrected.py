"""
Dataset Statistics Calculator for Corrected Dataset
This script calculates mean values for different attack types
from the corrected dataset (with manual labeling from ground truth).
"""

import pandas as pd
import numpy as np

# Load the corrected dataset
dataset_path = "ml-dataset-50-50-idle-timeout-2-17-10-2025-multiple-attacks-corrected.csv"
print(f"Loading corrected dataset from: {dataset_path}\n")

dataset = pd.read_csv(dataset_path)

print("=" * 80)
print("CORRECTED DATASET STATISTICS")
print("=" * 80)

# Basic dataset info
print(f"\nTotal rows: {len(dataset)}")
print(f"Total columns: {len(dataset.columns)}")

# Class distribution
print("\n" + "=" * 80)
print("CLASS DISTRIBUTION")
print("=" * 80)
print(f"\nNormal samples: {(dataset['attack'] == 0).sum()}")
print(f"Attack samples: {dataset['attack'].sum()}")
print(f"  - SYN attacks: {dataset['attack_syn'].sum()}")
print(f"  - UDP attacks: {dataset['attack_udp'].sum()}")
print(f"  - ICMP attacks: {dataset['attack_icmp'].sum()}")

# Calculate mean values for each class
print("\n" + "=" * 80)
print("MEAN VALUES BY CLASS")
print("=" * 80)

features = ['no_of_total_flows', 'no_of_tcp_flows', 'no_of_udp_flows', 'no_of_icmp_flows']

print("\nNormal samples (mean):")
normal_means = dataset[dataset['attack']==0][features].mean()
print(normal_means)

print("\nSYN attack samples (mean):")
syn_means = dataset[dataset['attack_syn']==1][features].mean()
print(syn_means)

print("\nUDP attack samples (mean):")
udp_means = dataset[dataset['attack_udp']==1][features].mean()
print(udp_means)

print("\nICMP attack samples (mean):")
icmp_means = dataset[dataset['attack_icmp']==1][features].mean()
print(icmp_means)

# Create comparison table with rounded values
print("\n" + "=" * 80)
print("COMPARISON TABLE (ROUNDED VALUES)")
print("=" * 80)

print("\n{:<20} {:<15} {:<15} {:<15} {:<15}".format(
    "Metryka", "Normal", "SYN", "UDP", "ICMP"
))
print("-" * 80)

# Total flows
print("{:<20} {:<15.0f} {:<15.0f} {:<15.0f} {:<15.0f}".format(
    "Przepływy ogółem",
    normal_means['no_of_total_flows'],
    syn_means['no_of_total_flows'],
    udp_means['no_of_total_flows'],
    icmp_means['no_of_total_flows']
))

# TCP flows
print("{:<20} {:<15.0f} {:<15.0f} {:<15.0f} {:<15.0f}".format(
    "Przepływy TCP",
    normal_means['no_of_tcp_flows'],
    syn_means['no_of_tcp_flows'],
    udp_means['no_of_tcp_flows'],
    icmp_means['no_of_tcp_flows']
))

# UDP flows
print("{:<20} {:<15.0f} {:<15.0f} {:<15.0f} {:<15.0f}".format(
    "Przepływy UDP",
    normal_means['no_of_udp_flows'],
    syn_means['no_of_udp_flows'],
    udp_means['no_of_udp_flows'],
    icmp_means['no_of_udp_flows']
))

# ICMP flows
print("{:<20} {:<15.0f} {:<15.0f} {:<15.0f} {:<15.0f}".format(
    "Przepływy ICMP",
    normal_means['no_of_icmp_flows'],
    syn_means['no_of_icmp_flows'],
    udp_means['no_of_icmp_flows'],
    icmp_means['no_of_icmp_flows']
))

# Calculate multipliers for attack types vs normal
print("\n" + "=" * 80)
print("MULTIPLIERS (attack vs normal)")
print("=" * 80)

print("\n{:<20} {:<15} {:<15} {:<15}".format(
    "Metryka", "SYN", "UDP", "ICMP"
))
print("-" * 80)

print("{:<20} {:<15.1f}x {:<15.1f}x {:<15.1f}x".format(
    "Przepływy ogółem",
    syn_means['no_of_total_flows'] / normal_means['no_of_total_flows'],
    udp_means['no_of_total_flows'] / normal_means['no_of_total_flows'],
    icmp_means['no_of_total_flows'] / normal_means['no_of_total_flows']
))

print("{:<20} {:<15.1f}x {:<15.1f}x {:<15.1f}x".format(
    "Przepływy TCP",
    syn_means['no_of_tcp_flows'] / normal_means['no_of_tcp_flows'],
    udp_means['no_of_tcp_flows'] / normal_means['no_of_tcp_flows'],
    icmp_means['no_of_tcp_flows'] / normal_means['no_of_tcp_flows']
))

print("{:<20} {:<15.1f}x {:<15.1f}x {:<15.1f}x".format(
    "Przepływy UDP",
    syn_means['no_of_udp_flows'] / normal_means['no_of_udp_flows'],
    udp_means['no_of_udp_flows'] / normal_means['no_of_udp_flows'],
    icmp_means['no_of_udp_flows'] / normal_means['no_of_udp_flows']
))

print("{:<20} {:<15.1f}x {:<15.1f}x {:<15.1f}x".format(
    "Przepływy ICMP",
    syn_means['no_of_icmp_flows'] / normal_means['no_of_icmp_flows'],
    udp_means['no_of_icmp_flows'] / normal_means['no_of_icmp_flows'],
    icmp_means['no_of_icmp_flows'] / normal_means['no_of_icmp_flows']
))

# LaTeX table format
print("\n" + "=" * 80)
print("LATEX TABLE FORMAT")
print("=" * 80)

latex_table = """
\\begin{{table}}[h]
\\centering
\\begin{{tabular}}{{|l|c|c|c|c|}}
\\hline
\\textbf{{Metryka}} & \\textbf{{Normal}} & \\textbf{{SYN}} & \\textbf{{UDP}} & \\textbf{{ICMP}} \\\\ \\hline
Przepływy ogółem & {0:.0f} & {1:.0f} ({2:.1f}×) & {3:.0f} ({4:.1f}×) & {5:.0f} ({6:.1f}×) \\\\ \\hline
Przepływy TCP & {7:.0f} & {8:.0f} ({9:.1f}×) & {10:.0f} ({11:.1f}×) & {12:.0f} ({13:.1f}×) \\\\ \\hline
Przepływy UDP & {14:.0f} & {15:.0f} ({16:.1f}×) & {17:.0f} ({18:.0f}×) & {19:.0f} ({20:.1f}×) \\\\ \\hline
Przepływy ICMP & {21:.0f} & {22:.0f} ({23:.1f}×) & {24:.0f} ({25:.1f}×) & {26:.0f} ({27:.0f}×) \\\\ \\hline
\\end{{tabular}}
\\caption{{Porównanie średnich wartości cech dla różnych klas ruchu (dataset skorygowany)}}
\\label{{tab:attack_comparison_corrected}}
\\end{{table}}
""".format(
    # Total flows
    normal_means['no_of_total_flows'],
    syn_means['no_of_total_flows'], syn_means['no_of_total_flows'] / normal_means['no_of_total_flows'],
    udp_means['no_of_total_flows'], udp_means['no_of_total_flows'] / normal_means['no_of_total_flows'],
    icmp_means['no_of_total_flows'], icmp_means['no_of_total_flows'] / normal_means['no_of_total_flows'],
    # TCP flows
    normal_means['no_of_tcp_flows'],
    syn_means['no_of_tcp_flows'], syn_means['no_of_tcp_flows'] / normal_means['no_of_tcp_flows'],
    udp_means['no_of_tcp_flows'], udp_means['no_of_tcp_flows'] / normal_means['no_of_tcp_flows'],
    icmp_means['no_of_tcp_flows'], icmp_means['no_of_tcp_flows'] / normal_means['no_of_tcp_flows'],
    # UDP flows
    normal_means['no_of_udp_flows'],
    syn_means['no_of_udp_flows'], syn_means['no_of_udp_flows'] / normal_means['no_of_udp_flows'],
    udp_means['no_of_udp_flows'], udp_means['no_of_udp_flows'] / normal_means['no_of_udp_flows'],
    icmp_means['no_of_udp_flows'], icmp_means['no_of_udp_flows'] / normal_means['no_of_udp_flows'],
    # ICMP flows
    normal_means['no_of_icmp_flows'],
    syn_means['no_of_icmp_flows'], syn_means['no_of_icmp_flows'] / normal_means['no_of_icmp_flows'],
    udp_means['no_of_icmp_flows'], udp_means['no_of_icmp_flows'] / normal_means['no_of_icmp_flows'],
    icmp_means['no_of_icmp_flows'], icmp_means['no_of_icmp_flows'] / normal_means['no_of_icmp_flows']
)

print(latex_table)

print("\n" + "=" * 80)
print("DONE")
print("=" * 80)