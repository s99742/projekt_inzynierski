#!/usr/bin/env python3
"""
predict_models.py
Predykcja przy użyciu RandomForest, LogisticRegression, HistGradientBoosting (HGB).
Po wykonaniu zapisuje log do sqlite3 (logs/project_logs.db) przez log_db.log_run().
"""

import os
import argparse
import joblib
import pandas as pd
import numpy as np
import sys

from log_db import log_run, create_db

MODEL_DIR = "../models/"
MODEL_FILES = {
    "rf": os.path.join(MODEL_DIR, "RandomForest_cicids.pkl"),
    "lr": os.path.join(MODEL_DIR, "LogisticRegression_cicids.pkl"),
    "hgb": os.path.join(MODEL_DIR, "HGB_cicids.pkl")
}

TRAIN_FEATURES_CSV = "../data/X_train.csv"
DEFAULT_Y_TEST = "../data/y_test.csv"
DEFAULT_DB = os.path.join(os.path.dirname(__file__), "..", "logs", "project_logs.db")

def parse_args():
    p = argparse.ArgumentParser(description="Predict with RF / LR / HGB models and optionally ensemble.")
    p.add_argument("--input", "-i", default="../data/X_test.csv", help="CSV z danymi do predykcji.")
    p.add_argument("--out", "-o", default="../data/predictions.csv", help="Ścieżka do zapisu wyników CSV.")
    p.add_argument("--rf", action="store_true", help="Włącz RandomForest")
    p.add_argument("--lr", action="store_true", help="Włącz LogisticRegression")
    p.add_argument("--hgb", action="store_true", help="Włącz HistGradientBoosting (HGB)")
    p.add_argument("--ensemble", action="store_true", help="Majority-vote ensemble")
    p.add_argument("--features-from", default=TRAIN_FEATURES_CSV, help="CSV z listą cech (X_train.csv)")
    p.add_argument("--ytest", default=DEFAULT_Y_TEST, help="(Opcjonalnie) CSV z prawdziwymi etykietami do policzenia metryk")
    return p.parse_args()

def ensure_features(input_df, features_csv):
    feat_df = pd.read_csv(features_csv, nrows=0)
    required_cols = list(feat_df.columns)
    if "Label" in input_df.columns:
        input_df = input_df.drop(columns=["Label"])
    for c in required_cols:
        if c not in input_df.columns:
            input_df[c] = 0
    extra = [c for c in input_df.columns if c not in required_cols]
    if extra:
        input_df = input_df.drop(columns=extra)
    input_df = input_df[required_cols]
    return input_df

def safe_load_model(path):
    if not os.path.exists(path):
        print(f"Model nie znaleziony: {path}")
        return None
    try:
        m = joblib.load(path)
        print(f"Załadowano model: {os.path.basename(path)}")
        return m
    except Exception as e:
        print(f"Błąd przy ładowaniu modelu {path}: {e}")
        return None

def predict_with_model(model, X, batch_size=5000):
    n = X.shape[0]
    preds = []
    confs = []
    for start in range(0, n, batch_size):
        end = min(start + batch_size, n)
        X_batch = X.iloc[start:end]
        try:
            p = model.predict(X_batch)
            preds.extend(p)
        except Exception:
            preds.extend([None] * len(X_batch))
        try:
            if hasattr(model, "predict_proba"):
                c = model.predict_proba(X_batch).max(axis=1)
                confs.extend(c)
            else:
                confs.extend([np.nan] * len(X_batch))
        except Exception:
            confs.extend([np.nan] * len(X_batch))
        print(f"Predykcja {model.__class__.__name__}: {start}/{n} wierszy", end="\r")
    print("")
    return {"pred": np.array(preds), "conf": np.array(confs)}

def majority_vote(preds_list):
    preds_stack = np.vstack(preds_list).T
    final = []
    for row in preds_stack:
        vals, counts = np.unique(row, return_counts=True)
        maxcount = counts.max()
        candidates = vals[counts == maxcount]
        if len(candidates) == 1:
            final.append(candidates[0])
        else:
            final.append(np.min(candidates))
    return np.array(final)

def safe_read_ytest(ytest_path, expected_len):
    """Spróbuj wczytać y_test tylko jeśli plik istnieje i długość się zgadza."""
    if not os.path.exists(ytest_path):
        return None
    try:
        y = pd.read_csv(ytest_path).values.ravel()
        if len(y) != expected_len:
            return None
        return y
    except Exception:
        return None

def main():
    args = parse_args()
    # ensure DB exists
    create_db(DEFAULT_DB)

    use_rf = bool(args.rf)
    use_lr = bool(args.lr)
    use_hgb = bool(args.hgb)
    if not (use_rf or use_lr or use_hgb):
        use_rf = use_lr = use_hgb = True

    print("Konfiguracja modeli:")
    print(f"  RandomForest: {use_rf}")
    print(f"  LogisticRegression: {use_lr}")
    print(f"  HGB: {use_hgb}")
    print(f"  Ensemble majority-vote: {args.ensemble}\n")

    if not os.path.exists(args.input):
        print(f"Plik wejściowy nie istnieje: {args.input}")
        sys.exit(1)
    in_df = pd.read_csv(args.input, low_memory=False)
    print(f"Wczytano dane: {in_df.shape[0]} wierszy, {in_df.shape[1]} kolumn")

    X = ensure_features(in_df, args.features_from)

    models_loaded = {}
    if use_rf:
        models_loaded["rf"] = safe_load_model(MODEL_FILES["rf"])
    if use_lr:
        models_loaded["lr"] = safe_load_model(MODEL_FILES["lr"])
    if use_hgb:
        models_loaded["hgb"] = safe_load_model(MODEL_FILES["hgb"])

    models_loaded = {k: v for k, v in models_loaded.items() if v is not None}
    if len(models_loaded) == 0:
        print("❌ Brak załadowanych modeli.")
        sys.exit(1)

    results = pd.DataFrame(index=range(X.shape[0]))
    preds_for_ensemble = []
    confs_for_ensemble = []

    for short_name, model in models_loaded.items():
        print(f"Rozpoczynam predykcję dla {short_name}...")
        out = predict_with_model(model, X)
        results[f"pred_{short_name}"] = out["pred"]
        results[f"conf_{short_name}"] = out["conf"]
        preds_for_ensemble.append(out["pred"])
        confs_for_ensemble.append(out["conf"])

    if args.ensemble and len(preds_for_ensemble) >= 1:
        results["pred_ensemble"] = majority_vote(preds_for_ensemble)
        conf_array = np.array(confs_for_ensemble)
        with np.errstate(invalid='ignore'):
            results["conf_ensemble"] = np.nanmean(conf_array, axis=0)
    else:
        results["pred_ensemble"] = np.nan
        results["conf_ensemble"] = np.nan

    # Zapis wyników
    out_path = args.out
    results.to_csv(out_path, index=False)
    print(f"\n🎉 Zapisano predykcje do: {out_path}")
    print(results.head(10))

    y_test = safe_read_ytest(args.ytest, len(results))
    accuracy = None
    f1 = None
    notes = None
    if y_test is not None and "pred_ensemble" in results.columns and not results["pred_ensemble"].isna().all():
        try:
            from sklearn.metrics import accuracy_score, f1_score
            mask = ~pd.isna(results["pred_ensemble"].values)
            y_true_valid = y_test[mask]
            y_pred_valid = results.loc[mask, "pred_ensemble"].astype(int).values
            accuracy = float(accuracy_score(y_true_valid, y_pred_valid))
            f1 = float(f1_score(y_true_valid, y_pred_valid, average="weighted"))
        except Exception as e:
            notes = f"Error computing metrics: {e}"

    models_used = ",".join(list(models_loaded.keys()))
    # zapisz log
    log_run(script="predict_models",
            n_rows=int(X.shape[0]),
            models_used=models_used,
            ensemble_used=bool(args.ensemble),
            accuracy=accuracy,
            f1_score=f1,
            notes=notes,
            db_path=DEFAULT_DB)

if __name__ == "__main__":
    main()
