import time
import joblib
import numpy as np
import matplotlib.pyplot as plt
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score

# ------------------------------
# ŚCIEŻKI
# ------------------------------
X_train_path = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski/data/X_train.pkl"
y_train_path = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski/data/y_train.pkl"

X_test_path = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski/data/X_test.pkl"
y_test_path = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski/data/y_test.pkl"

MODEL_OUT = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski/models/MLP_fast_v2.pkl"
LOSS_PLOT = "/home/jakub-wasiewicz/Desktop/inzynierka/projekt_inzynierski/models/MLP_fast_v2_loss.png"

# ------------------------------
# ŁADOWANIE DANYCH
# ------------------------------
print("📥 Wczytywanie danych...")
X_train = joblib.load(X_train_path)
y_train = joblib.load(y_train_path)
X_test = joblib.load(X_test_path)
y_test = joblib.load(y_test_path)

print("✔️ Dane wczytane!")
print("  X_train:", X_train.shape)
print("  y_train:", len(y_train))

# ------------------------------
# MODEL (szybka wersja)
# ------------------------------
mlp = MLPClassifier(
    hidden_layer_sizes=(80, 40),
    activation="relu",
    solver="adam",
    learning_rate="adaptive",
    max_iter=200,
    batch_size=256,
    shuffle=True,
    verbose=True,
    early_stopping=True,
    n_iter_no_change=10,
)

pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("mlp", mlp)
])

# ------------------------------
# TRENING
# ------------------------------
print("\n🚀 Start treningu")
start_time = time.time()

pipeline.fit(X_train, y_train)

end_time = time.time()
elapsed = end_time - start_time
print(f"Trening zakończony w {elapsed:.2f} sek ({elapsed/60:.1f} minut)")

# ------------------------------
# EWALUACJA
# ------------------------------
y_pred = pipeline.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"\nAccuracy na pełnym teście: {acc:.4f}")

# ------------------------------
# ZAPIS MODELU
# ------------------------------
joblib.dump(pipeline, MODEL_OUT)
print(f"Model zapisany do: {MODEL_OUT}")

# ------------------------------
# WYKRES LOSS CURVE
# ------------------------------
mlp_part = pipeline.named_steps["mlp"]

plt.figure(figsize=(8,5))
plt.plot(mlp_part.loss_curve_)
plt.title("MLP Loss Curve (fast version)")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.grid(True)
plt.tight_layout()
plt.savefig(LOSS_PLOT)

print(f"Wykres loss zapisany jako: {LOSS_PLOT}")
