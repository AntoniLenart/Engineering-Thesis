import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

df = pd.read_csv('ml-dataset-50-50-idle-timeout-2-17-10-2025-multiple-attacks-corrected.csv')

df['is_syn'] = df['attack_syn'] == 1
df['prev_is_syn'] = df['is_syn'].shift(1, fill_value=False)
df['next_is_syn'] = df['is_syn'].shift(-1, fill_value=False)
df['syn_start'] = (~df['prev_is_syn']) & df['is_syn']
df['syn_end'] = df['is_syn'] & (~df['next_is_syn'])

syn_starts = df[df['syn_start']].index.tolist()
syn_ends = df[df['syn_end']].index.tolist()

attack_idx = 1  # Atak #2
start = syn_starts[attack_idx]
end = syn_ends[attack_idx]

window_start = max(0, start - 5)
window_end = min(len(df) - 1, end + 15)

df_window = df.iloc[window_start:window_end+1].copy()
df_window['sample_idx'] = range(window_start, window_end + 1)

fig, axes = plt.subplots(3, 1, figsize=(14, 10), sharex=True)

metrics = [
    ('total_flows_10s', 'Total Flows (10s window)', 0),
    ('no_of_tcp_flows', 'Number of TCP Flows', 1),
    ('table_active_count_mean', 'Table Active Count (mean)', 2)
]

for metric_name, metric_label, ax_idx in metrics:
    ax = axes[ax_idx]

    ax.plot(df_window['sample_idx'], df_window[metric_name],
            marker='o', linewidth=2, markersize=6, color='darkblue', label=metric_label)

    for idx in df_window['sample_idx']:
        row = df_window[df_window['sample_idx'] == idx].iloc[0]

        if idx < start:
            ax.axvspan(idx - 0.5, idx + 0.5, alpha=0.2, color='green')
        elif start <= idx <= end:
            ax.axvspan(idx - 0.5, idx + 0.5, alpha=0.3, color='red')
        elif end < idx <= end + 3:
            if row['attack'] == 1:
                ax.axvspan(idx - 0.5, idx + 0.5, alpha=0.3, color='orange')
            else:
                ax.axvspan(idx - 0.5, idx + 0.5, alpha=0.3, color='yellow')
        elif end + 3 < idx <= end + 7:
            ax.axvspan(idx - 0.5, idx + 0.5, alpha=0.25, color='lightyellow')
        elif end + 7 < idx <= end + 12:
            ax.axvspan(idx - 0.5, idx + 0.5, alpha=0.15, color='lightblue')
        else:
            ax.axvspan(idx - 0.5, idx + 0.5, alpha=0.1, color='green')

    ax.set_ylabel(metric_label, fontsize=11, fontweight='bold')
    ax.grid(True, alpha=0.3)
    ax.set_xlim(window_start - 0.5, window_end + 0.5)

for ax in axes:
    ax.axvline(start, color='red', linestyle='--', linewidth=2, label='Attack Start')
    ax.axvline(end, color='darkred', linestyle='--', linewidth=2, label='Attack End')
    ax.axvline(end + 0.5, color='purple', linestyle=':', linewidth=1.5, alpha=0.7)

axes[0].legend(loc='upper left', fontsize=9)

axes[2].set_xlabel('Sample Index', fontsize=12, fontweight='bold')
axes[2].set_xticks(df_window['sample_idx'][::2])  # Co drugą próbkę

fig.suptitle(f'Idle Timeout Effect (2s) on Metrics After SYN Attack Termination\n'
             f'Attack #{attack_idx + 1} (indices {start}-{end})',
             fontsize=14, fontweight='bold')

legend_elements = [
    mpatches.Patch(color='green', alpha=0.2, label='Normal (before attack)'),
    mpatches.Patch(color='red', alpha=0.3, label='SYN Attack'),
    mpatches.Patch(color='yellow', alpha=0.3, label='Post +1-3s (NORMAL) ← FALSE POSITIVE'),
    mpatches.Patch(color='lightyellow', alpha=0.25, label='Transition +4-7s (early)'),
    mpatches.Patch(color='lightblue', alpha=0.15, label='Transition +8-12s (late)'),
    mpatches.Patch(color='green', alpha=0.1, label='Normalized +13s+')
]

fig.legend(handles=legend_elements, loc='lower center', ncol=3,
           fontsize=7, bbox_to_anchor=(0.5, -0.015))

plt.tight_layout(rect=[0, 0.03, 1, 0.96])
plt.savefig('syn_idle_timeout_boundary_effect_fixed.png', dpi=300, bbox_inches='tight')
print("Wykres zapisany: syn_idle_timeout_boundary_effect_fixed.png")

fig2, axes2 = plt.subplots(2, 2, figsize=(14, 10))

post_attack_data = []

for i, (start, end) in enumerate(zip(syn_starts, syn_ends)):
    for offset in [1, 2, 3]:
        idx = end + offset
        if idx < len(df):
            post_attack_data.append({
                'attack_id': i + 1,
                'offset': offset,
                'is_labeled_attack': df.loc[idx, 'attack'],
                'total_flows_10s': df.loc[idx, 'total_flows_10s'],
                'no_of_tcp_flows': df.loc[idx, 'no_of_tcp_flows'],
                'table_active_count_mean': df.loc[idx, 'table_active_count_mean']
            })

post_df = pd.DataFrame(post_attack_data)

ax1 = axes2[0, 0]
labeled_attack = post_df[post_df['is_labeled_attack'] == 1]
labeled_normal = post_df[post_df['is_labeled_attack'] == 0]

x_pos = np.arange(2)
means_flows = [labeled_attack['total_flows_10s'].mean(), labeled_normal['total_flows_10s'].mean()]
ax1.bar(x_pos, means_flows, color=['orange', 'yellow'], alpha=0.7, edgecolor='black')
ax1.set_xticks(x_pos)
ax1.set_xticklabels(['Labeled as\nATTACK', 'Labeled as\nNORMAL'])
ax1.set_ylabel('Average total_flows_10s', fontweight='bold')
ax1.set_title('Post-Attack Samples: Flow Count by Label', fontweight='bold')
ax1.grid(axis='y', alpha=0.3)

normal_avg = df[df['attack'] == 0]['total_flows_10s'].mean()
ax1.axhline(normal_avg, color='green', linestyle='--', linewidth=2, label=f'Normal avg: {normal_avg:.0f}')
ax1.legend()

ax2 = axes2[0, 1]
offset_counts = post_df.groupby(['offset', 'is_labeled_attack']).size().unstack(fill_value=0)
offset_counts.plot(kind='bar', ax=ax2, color=['orange', 'yellow'], alpha=0.7, edgecolor='black')
ax2.set_xlabel('Time Offset (x10s)', fontweight='bold')
ax2.set_ylabel('Number of Samples', fontweight='bold')
ax2.set_title('Post-Attack Samples Distribution', fontweight='bold')
ax2.legend(['Labeled as ATTACK', 'Labeled as NORMAL (FALSE POSITIVE)'])
ax2.set_xticklabels(['+10s', '+20s', '+30s'], rotation=0)
ax2.grid(axis='y', alpha=0.3)

ax3 = axes2[1, 0]
means_tcp = [labeled_attack['no_of_tcp_flows'].mean(), labeled_normal['no_of_tcp_flows'].mean()]
ax3.bar(x_pos, means_tcp, color=['orange', 'yellow'], alpha=0.7, edgecolor='black')
ax3.set_xticks(x_pos)
ax3.set_xticklabels(['Labeled as\nATTACK', 'Labeled as\nNORMAL'])
ax3.set_ylabel('Average no_of_tcp_flows', fontweight='bold')
ax3.set_title('Post-Attack Samples: TCP Flows by Label', fontweight='bold')
ax3.grid(axis='y', alpha=0.3)

normal_tcp_avg = df[df['attack'] == 0]['no_of_tcp_flows'].mean()
ax3.axhline(normal_tcp_avg, color='green', linestyle='--', linewidth=2, label=f'Normal avg: {normal_tcp_avg:.0f}')
ax3.legend()

ax4 = axes2[1, 1]
means_table = [labeled_attack['table_active_count_mean'].mean(), labeled_normal['table_active_count_mean'].mean()]
ax4.bar(x_pos, means_table, color=['orange', 'yellow'], alpha=0.7, edgecolor='black')
ax4.set_xticks(x_pos)
ax4.set_xticklabels(['Labeled as\nATTACK', 'Labeled as\nNORMAL'])
ax4.set_ylabel('Average table_active_count_mean', fontweight='bold')
ax4.set_title('Post-Attack Samples: Table Active Count by Label', fontweight='bold')
ax4.grid(axis='y', alpha=0.3)

normal_table_avg = df[df['attack'] == 0]['table_active_count_mean'].mean()
ax4.axhline(normal_table_avg, color='green', linestyle='--', linewidth=2, label=f'Normal avg: {normal_table_avg:.0f}')
ax4.legend()

fig2.suptitle('Post-Attack Sample Analysis for SYN Attacks\nIdle Timeout (2s) Impact on Precision',
              fontsize=14, fontweight='bold')

plt.tight_layout()
plt.savefig('syn_post_attack_statistics_fixed.png', dpi=300, bbox_inches='tight')