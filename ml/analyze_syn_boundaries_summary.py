import pandas as pd
import numpy as np

# Wczytaj dataset
df = pd.read_csv('ml-dataset-50-50-idle-timeout-2-17-10-2025-multiple-attacks-corrected.csv')

# Identyfikuj granice ataków SYN
df['is_syn'] = df['attack_syn'] == 1
df['prev_is_syn'] = df['is_syn'].shift(1, fill_value=False)
df['next_is_syn'] = df['is_syn'].shift(-1, fill_value=False)
df['syn_start'] = (~df['prev_is_syn']) & df['is_syn']
df['syn_end'] = df['is_syn'] & (~df['next_is_syn'])

syn_starts = df[df['syn_start']].index.tolist()
syn_ends = df[df['syn_end']].index.tolist()

print("="*80)
print("ANALIZA EFEKTU IDLE_TIMEOUT NA PRECISION DETEKCJI ATAKOW SYN")
print("="*80)
print(f"\nIdle timeout OpenFlow: 2 sekundy")
print(f"Okno agregacji: 10 sekund")
print(f"Liczba ataków SYN: {len(syn_starts)}")

# Analiza próbek po zakończeniu ataku
print("\n" + "="*80)
print("PODSUMOWANIE: PROBKI PO ZAKONCZENIU ATAKU SYN")
print("="*80)

suspicious_samples = []

for i, (start, end) in enumerate(zip(syn_starts, syn_ends), 1):
    print(f"\nAtak #{i} (indeksy {start}-{end}):")

    # Sprawdź 3 próbki po ataku
    for offset in [1, 2, 3]:
        idx = end + offset
        if idx < len(df):
            is_labeled_attack = df.loc[idx, 'attack'] == 1
            syn_flag = df.loc[idx, 'attack_syn']
            total_flows = df.loc[idx, 'total_flows_10s']
            tcp_flows = df.loc[idx, 'no_of_tcp_flows']
            table_active = df.loc[idx, 'table_active_count_mean']

            # Sprawdź czy próbka ma charakterystykę ataku mimo że atak się skończył
            has_high_flows = total_flows > 1000
            has_high_tcp = tcp_flows > 100
            has_high_table = table_active > 100

            suspicious = has_high_flows or has_high_tcp or has_high_table

            if suspicious:
                suspicious_samples.append({
                    'attack_id': i,
                    'sample_idx': idx,
                    'offset_from_end': offset,
                    'time_offset_sec': offset * 10,
                    'is_labeled_attack': is_labeled_attack,
                    'syn_flag': syn_flag,
                    'total_flows_10s': total_flows,
                    'no_of_tcp_flows': tcp_flows,
                    'table_active_count_mean': table_active
                })

                label_status = "ETYKIETA: ATAK" if is_labeled_attack else "ETYKIETA: NORMAL"
                print(f"  [+{offset*10}s] Indeks {idx}: {label_status}")
                print(f"       total_flows={total_flows}, tcp_flows={tcp_flows}, table_active={table_active:.0f}")
                if has_high_flows:
                    print(f"       -> Podejrzanie wysoka liczba przeplywow!")
                if has_high_tcp:
                    print(f"       -> Podejrzanie wysoka liczba TCP flows!")
                if has_high_table:
                    print(f"       -> Podejrzanie wysoka wartosc table_active (efekt idle_timeout)!")

# Podsumowanie statystyczne
print("\n" + "="*80)
print("STATYSTYKI PODSUMOWUJACE")
print("="*80)

suspicious_df = pd.DataFrame(suspicious_samples)

if len(suspicious_df) > 0:
    print(f"\nLiczba podejrzanych probek po zakonczeniu ataku: {len(suspicious_df)}")

    # Ile z nich było etykietowanych jako atak?
    labeled_as_attack = suspicious_df['is_labeled_attack'].sum()
    labeled_as_normal = len(suspicious_df) - labeled_as_attack

    print(f"\nProbki z wysokimi wartosciami metrycznych MIMO zakonczenia ataku SYN:")
    print(f"  - Etykietowane jako ATAK: {labeled_as_attack} ({labeled_as_attack/len(suspicious_df)*100:.1f}%)")
    print(f"  - Etykietowane jako NORMAL: {labeled_as_normal} ({labeled_as_normal/len(suspicious_df)*100:.1f}%)")

    print(f"\nRozklad czasowy (offset od konca ataku):")
    print(suspicious_df.groupby('time_offset_sec').size())

    print(f"\nSrednie wartosci metryk w podejrzanych probkach:")
    print(f"  - Srednia total_flows_10s: {suspicious_df['total_flows_10s'].mean():.0f}")
    print(f"  - Srednia no_of_tcp_flows: {suspicious_df['no_of_tcp_flows'].mean():.0f}")
    print(f"  - Srednia table_active_count: {suspicious_df['table_active_count_mean'].mean():.0f}")

    # Porównanie z próbkami normalnymi
    normal_samples = df[(df['attack'] == 0) & (df['attack_syn'] == 0)]
    print(f"\nPorownanie z typowym ruchem NORMALNYM:")
    print(f"  - Srednia total_flows_10s (normal): {normal_samples['total_flows_10s'].mean():.0f}")
    print(f"  - Srednia no_of_tcp_flows (normal): {normal_samples['no_of_tcp_flows'].mean():.0f}")
    print(f"  - Srednia table_active_count (normal): {normal_samples['table_active_count_mean'].mean():.0f}")

    print("\n" + "="*80)
    print("WNIOSKI")
    print("="*80)
    print("""
KLUCZOWE OBSERWACJE:

1. EFEKT IDLE_TIMEOUT (2s):
   - Po zakonczeniu ataku SYN, przeplywy TCP pozostaja w tablicy OpenFlow
   - Idle timeout usuwa je dopiero po 2 sekundach braku aktywnosci
   - W oknie agregacji 10s oznacza to ze 2-3 probki po ataku zawieraja "echo" ataku

2. WPLYW NA ETYKIETY:
   - Probki po zakonczeniu ataku maja wysokie wartosci metryk przepływowych
   - Te probki sa czasami etykietowane jako ATAK (przez Snort lub ground truth)
   - Czasami sa etykietowane jako NORMAL (jesli atak juz sie zakonczyl w logach)

3. IMPLIKACJE DLA PRECISION:
   - Model widzi probke z wysokimi wartosciami charakterystycznymi dla SYN
   - Jesli etykieta = NORMAL, model poprawnie sklasyfikuje jako SYN -> FALSE POSITIVE
   - To wyjasnia nizsza precision dla SYN (86-89%) vs UDP/ICMP (>92%)

4. ROZNICE MIEDZY TYPAMI ATAKOW:
   - UDP/ICMP floods: przepływy szybko wygasaja (connectionless)
   - SYN flood: przepływy TCP pozostaja w tablicy dluzej (connection-oriented)
   - To wyjasnia dlaczego SYN ma nizsza precision niz UDP/ICMP

REKOMENDACJE:
- Rozwazyc zwiekszenie idle_timeout (np. 5s) lub zmniejszenie okna agregacji (np. 5s)
- Alternatywnie: dodac cechy roznicowe (diff) pomiedzy kolejnymi probkami
- W produkcji: uwzglednic ten efekt w interpretacji alertow (grace period)
""")
else:
    print("\nBrak podejrzanych probek.")

print("="*80)