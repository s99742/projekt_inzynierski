import random
import numpy as np

def generate_synthetic_flow(label="BENIGN"):
    """
    Tworzy syntetyczny flow z 78 cechami kompatybilnymi z CICIDS2017.
    label = "BENIGN" albo "ATTACK"
    Zwraca: numpy.array shape (78,)
    """

    if label == "BENIGN":
        total_fwd = random.randint(10, 80)
        total_bwd = random.randint(5, 60)
        duration = random.randint(2000, 200000)      # 2 ms - 200 ms
        pkt_size_base = random.randint(40, 400)
    else:
        # ATTACK → duże flowy, szybkie tempo, burst pattern
        total_fwd = random.randint(150, 500)
        total_bwd = random.randint(80, 300)
        duration = random.randint(200, 3000)         # ekstremalnie szybkie flow
        pkt_size_base = random.randint(400, 1400)

    total_pkts = total_fwd + total_bwd

    # Wygeneruj losowe pakiety
    fwd_sizes = np.random.normal(pkt_size_base, pkt_size_base/4, total_fwd).clip(20, 1500)
    bwd_sizes = np.random.normal(pkt_size_base/1.5, pkt_size_base/3, total_bwd).clip(20, 1500)

    # Times (IAT)
    fwd_iat = np.abs(np.random.normal(duration/total_fwd, duration/(total_fwd*3), total_fwd))
    bwd_iat = np.abs(np.random.normal(duration/total_bwd, duration/(total_bwd*3), total_bwd))

    # Konwersja na cechy (tak jak w CICIDS2017 — uproszczone, ale zgodne z formatem)
    features = [
        random.randint(1, 65535),                          # Destination Port
        duration,                                           # Flow Duration
        total_fwd,                                          # Total Fwd Packets
        total_bwd,                                          # Total Backward Packets
        fwd_sizes.sum(),                                    # Total Len Fwd
        bwd_sizes.sum(),                                    # Total Len Bwd
        fwd_sizes.max(),
        fwd_sizes.min(),
        fwd_sizes.mean(),
        fwd_sizes.std(),
        bwd_sizes.max(),
        bwd_sizes.min(),
        bwd_sizes.mean(),
        bwd_sizes.std(),

        # Flow Bytes/s
        (fwd_sizes.sum() + bwd_sizes.sum()) / duration * 1000,
        # Flow Packets/s
        total_pkts / duration * 1000,

        # Flow IAT
        np.concatenate([fwd_iat, bwd_iat]).mean(),
        np.concatenate([fwd_iat, bwd_iat]).std(),
        np.concatenate([fwd_iat, bwd_iat]).max(),
        np.concatenate([fwd_iat, bwd_iat]).min(),

        # FWD IAT
        fwd_iat.sum(),
        fwd_iat.mean(),
        fwd_iat.std(),
        fwd_iat.max(),
        fwd_iat.min(),

        # BWD IAT
        bwd_iat.sum(),
        bwd_iat.mean(),
        bwd_iat.std(),
        bwd_iat.max(),
        bwd_iat.min(),

        # Flags
        random.randint(0, 1),  # Fwd PSH
        random.randint(0, 1),  # Bwd PSH
        random.randint(0, 1),  # Fwd URG
        random.randint(0, 1),  # Bwd URG

        random.randint(20, 60),  # Fwd Header Length
        random.randint(20, 60),  # Bwd Header Length

        # Packet rates
        total_fwd / (duration / 1000),
        total_bwd / (duration / 1000),

        # Packet length global
        min(fwd_sizes.min(), bwd_sizes.min()),
        max(fwd_sizes.max(), bwd_sizes.max()),
        np.concatenate([fwd_sizes, bwd_sizes]).mean(),
        np.concatenate([fwd_sizes, bwd_sizes]).std(),
        np.concatenate([fwd_sizes, bwd_sizes]).var(),

        # Flag counters (random)
        random.randint(0, 1),  # FIN
        random.randint(0, 1),  # SYN
        random.randint(0, 1),  # RST
        random.randint(0, 1),  # PSH
        random.randint(0, 1),  # ACK
        random.randint(0, 1),  # URG
        random.randint(0, 1),  # CWE
        random.randint(0, 1),  # ECE

        # Down/Up ratio
        total_bwd / total_fwd if total_fwd else 0,

        # Avg Packet Size
        (np.concatenate([fwd_sizes, bwd_sizes]).mean()),

        # Avg Segment Sizes
        fwd_sizes.mean(),
        bwd_sizes.mean(),

        # Duplicate field in dataset
        random.randint(20, 60),    # Fwd Header Length (duplicate)

        # Bulk features — ustawione na 0 (tak było w dataset)
        0, 0, 0, 0, 0, 0,

        # Subflow
        total_fwd, fwd_sizes.sum(), total_bwd, bwd_sizes.sum(),

        # Window sizes
        random.randint(0, 60000),
        random.randint(0, 60000),

        # Act data pkt fwd
        random.randint(0, total_fwd),

        # Minimum segment size
        20,

        # Active / Idle
        random.random() * 5000,
        random.random() * 2000,
        random.random() * 7000,
        random.random() * 100,

        random.random() * 10000,
        random.random() * 3000,
        random.random() * 15000,
        random.random() * 100,
    ]

    return np.array(features, dtype=float)
