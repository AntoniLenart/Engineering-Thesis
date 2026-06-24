import pandas as pd
import numpy as np

# Wczytaj dataset
df = pd.read_csv('ml-dataset-50-50-idle-timeout-2-17-10-2025-multiple-attacks-corrected.csv')

print("=== INFORMACJE O DATASECIE ===")
print(f"Liczba próbek: {len(df)}")
print(f"Rozkład wartości w kolumnie 'attack':")
print(df['attack'].value_counts().sort_values(ascending=False))

# Identyfikuj granice ataków SYN
df['is_syn'] = df['attack_syn'] == 1
df['prev_is_syn'] = df['is_syn'].shift(1, fill_value=False)
df['next_is_syn'] = df['is_syn'].shift(-1, fill_value=False)

# Znajdź początki i końce ataków SYN
df['syn_start'] = (~df['prev_is_syn']) & df['is_syn']
df['syn_end'] = df['is_syn'] & (~df['next_is_syn'])

print(f"\n=== GRANICE ATAKÓW SYN ===")
print(f"Liczba początków ataków SYN: {df['syn_start'].sum()}")
print(f"Liczba końców ataków SYN: {df['syn_end'].sum()}")

# Wyświetl szczegóły każdego ataku SYN
syn_starts = df[df['syn_start']].index.tolist()
syn_ends = df[df['syn_end']].index.tolist()

print(f"\n=== SZCZEGÓŁY ATAKÓW SYN ===")
for i, (start, end) in enumerate(zip(syn_starts, syn_ends), 1):
    duration = end - start + 1
    print(f"\n{'='*60}")
    print(f"ATAK SYN #{i}:")
    print(f"{'='*60}")
    print(f"  Indeksy: {start} - {end} (długość: {duration} próbek = {duration * 10} sekund)")
    print(f"  Timestamp start: {df.loc[start, 'timestamp']}")
    print(f"  Timestamp end: {df.loc[end, 'timestamp']}")

    # Analiza próbek przed atakiem (jeśli są)
    print(f"\n  --- PRÓBKI PRZED ATAKIEM ---")
    if start >= 3:
        for offset in [3, 2, 1]:
            idx = start - offset
            print(f"\n  Próbka [{idx}] ({offset} próbek przed początkiem ataku, -{offset*10}s):")
            print(f"    Timestamp: {df.loc[idx, 'timestamp']}")
            print(f"    Attack: {df.loc[idx, 'attack']}")
            print(f"    SYN flag: {df.loc[idx, 'attack_syn']}")
            print(f"    total_flows_10s: {df.loc[idx, 'total_flows_10s']}")
            print(f"    no_of_total_flows: {df.loc[idx, 'no_of_total_flows']}")
            print(f"    table_active_count_mean: {df.loc[idx, 'table_active_count_mean']:.2f}")
            print(f"    flow_packet_count_mean: {df.loc[idx, 'flow_packet_count_mean']:.2f}")
            print(f"    no_of_tcp_flows: {df.loc[idx, 'no_of_tcp_flows']}")

    # Pierwsza próbka ataku
    print(f"\n  --- PIERWSZA PRÓBKA ATAKU ---")
    print(f"\n  Próbka [{start}] (początek ataku):")
    print(f"    Timestamp: {df.loc[start, 'timestamp']}")
    print(f"    Attack: {df.loc[start, 'attack']}")
    print(f"    total_flows_10s: {df.loc[start, 'total_flows_10s']}")
    print(f"    no_of_total_flows: {df.loc[start, 'no_of_total_flows']}")
    print(f"    table_active_count_mean: {df.loc[start, 'table_active_count_mean']:.2f}")
    print(f"    flow_packet_count_mean: {df.loc[start, 'flow_packet_count_mean']:.2f}")
    print(f"    no_of_tcp_flows: {df.loc[start, 'no_of_tcp_flows']}")

    # Ostatnia próbka ataku
    print(f"\n  --- OSTATNIA PRÓBKA ATAKU ---")
    print(f"\n  Próbka [{end}] (koniec ataku):")
    print(f"    Timestamp: {df.loc[end, 'timestamp']}")
    print(f"    Attack: {df.loc[end, 'attack']}")
    print(f"    total_flows_10s: {df.loc[end, 'total_flows_10s']}")
    print(f"    no_of_total_flows: {df.loc[end, 'no_of_total_flows']}")
    print(f"    table_active_count_mean: {df.loc[end, 'table_active_count_mean']:.2f}")
    print(f"    flow_packet_count_mean: {df.loc[end, 'flow_packet_count_mean']:.2f}")
    print(f"    no_of_tcp_flows: {df.loc[end, 'no_of_tcp_flows']}")

    # Analiza próbek po ataku (jeśli są)
    print(f"\n  --- PRÓBKI PO ATAKU (HIPOTEZA IDLE_TIMEOUT) ---")
    if end < len(df) - 3:
        for offset in [1, 2, 3]:
            idx = end + offset
            print(f"\n  Próbka [{idx}] ({offset} próbek po końcu ataku, +{offset*10}s):")
            print(f"    Timestamp: {df.loc[idx, 'timestamp']}")
            print(f"    Attack: {df.loc[idx, 'attack']}")
            print(f"    SYN flag: {df.loc[idx, 'attack_syn']}")
            print(f"    total_flows_10s: {df.loc[idx, 'total_flows_10s']}")
            print(f"    no_of_total_flows: {df.loc[idx, 'no_of_total_flows']}")
            print(f"    table_active_count_mean: {df.loc[idx, 'table_active_count_mean']:.2f}")
            print(f"    flow_packet_count_mean: {df.loc[idx, 'flow_packet_count_mean']:.2f}")
            print(f"    no_of_tcp_flows: {df.loc[idx, 'no_of_tcp_flows']}")

            # KLUCZOWA OBSERWACJA: sprawdź czy próbka po ataku ma wysokie wartości sugerujące "echo" ataku
            if df.loc[idx, 'total_flows_10s'] > 50:  # próg dla podejrzanej aktywności
                print(f"    [!] UWAGA: Wysoka wartosc total_flows_10s po zakonczeniu ataku!")
            if df.loc[idx, 'table_active_count_mean'] > 100:
                print(f"    [!] UWAGA: Wysoka wartosc table_active_count_mean - mozliwy efekt idle_timeout!")
            if df.loc[idx, 'no_of_tcp_flows'] > 50:
                print(f"    [!] UWAGA: Wysoka liczba przeplywow TCP po zakonczeniu ataku SYN!")

print("\n" + "="*60)
print("KONIEC ANALIZY")
print("="*60)