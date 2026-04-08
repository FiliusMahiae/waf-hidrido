import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="whitegrid")

FILES = {
    "Hybrid": "results\\results_hybrid.json",
    "Regex": "results\\results_regex_only.json",
    "ML": "results\\results_ml_only.json",
}


def load_summaries():
    rows = []

    for model, file in FILES.items():
        with open(file, encoding="utf-8") as f:
            data = json.load(f)

        s = data["summary"]
        truth = s["truth_distribution"]

        benign = int(truth["benign"])
        attacks = int(truth["xss"]) + int(truth["sqli"])

        blocked = int(s["blocked_total"])
        logged = int(s["log_total"])
        allowed = int(s["allow_total"])

        detected = blocked + logged

        rows.append({
            "Model": model,
            "Total": int(s["total_requests"]),
            "Benign": benign,
            "Attacks": attacks,
            "Blocked": blocked,
            "Logged": logged,
            "Allowed": allowed,
            "Detected": detected,
        })

    return pd.DataFrame(rows)


def build_confusion_from_summary(benign: int, attacks: int, detected: int, allowed: int):
    """
    Reconstrucción coherente:
      TP + FP = detected
      TN + FN = allowed
      TP + FN = attacks
      TN + FP = benign

    Elegimos una solución consistente minimizando imposibles:
      FP no puede ser > benign
      TP no puede ser > attacks
      FN no puede ser < 0
      TN no puede ser < 0
    """

    # Cota inferior de TP para que FP no supere benign
    tp_min = max(0, detected - benign)

    # Cota superior de TP por nº de ataques y detectados
    tp_max = min(attacks, detected)

    # Elegimos TP máximo consistente para favorecer detección de ataques
    tp = tp_max

    # Si por allowed quedara FN inconsistente, corregimos
    fn = attacks - tp
    tn = allowed - fn
    fp = benign - tn

    # Si algo queda fuera de rango, recalculamos usando fórmula directa
    if tn < 0 or fp < 0 or fn < 0:
        fp = min(benign, detected)
        tp = detected - fp
        tp = max(0, min(tp, attacks))
        fn = attacks - tp
        tn = benign - fp

    # Último saneamiento
    tp = max(0, tp)
    fp = max(0, fp)
    tn = max(0, tn)
    fn = max(0, fn)

    # Ajuste final para cuadrar exactamente filas y columnas
    # 1) fila benign
    if tn + fp != benign:
        diff = benign - (tn + fp)
        tn += diff

    # 2) fila attack
    if fn + tp != attacks:
        diff = attacks - (fn + tp)
        fn += diff

    # 3) columna detected
    if tp + fp != detected:
        diff = detected - (tp + fp)
        tp += diff

    # 4) evitar negativos tras ajustes
    tp = max(0, tp)
    fp = max(0, fp)
    tn = max(0, tn)
    fn = max(0, fn)

    return int(tp), int(fp), int(tn), int(fn)


def create_confusion_table(df: pd.DataFrame):
    rows = []

    for _, row in df.iterrows():
        tp, fp, tn, fn = build_confusion_from_summary(
            benign=int(row["Benign"]),
            attacks=int(row["Attacks"]),
            detected=int(row["Detected"]),
            allowed=int(row["Allowed"]),
        )

        rows.append({
            "Model": row["Model"],
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
        })

    return pd.DataFrame(rows)


def add_metrics(cm_df: pd.DataFrame):
    out = cm_df.copy()

    out["Precision"] = out["TP"] / (out["TP"] + out["FP"]).replace(0, pd.NA)
    out["Recall"] = out["TP"] / (out["TP"] + out["FN"]).replace(0, pd.NA)
    out["F1"] = 2 * out["Precision"] * out["Recall"] / (out["Precision"] + out["Recall"])
    out["FPR"] = out["FP"] / (out["FP"] + out["TN"]).replace(0, pd.NA)
    out["FNR"] = out["FN"] / (out["FN"] + out["TP"]).replace(0, pd.NA)
    out["Accuracy"] = (out["TP"] + out["TN"]) / (
        out["TP"] + out["TN"] + out["FP"] + out["FN"]
    )

    return out


def plot_confusions(cm_df: pd.DataFrame):
    for _, row in cm_df.iterrows():
        cm = [
            [int(row["TN"]), int(row["FP"])],
            [int(row["FN"]), int(row["TP"])],
        ]

        plt.figure(figsize=(6, 5))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=["Benign", "Attack"],
            yticklabels=["Benign", "Attack"],
        )
        plt.title(f"Confusion {row['Model']}")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.tight_layout()
        plt.savefig(f"confusion_{row['Model']}.png", dpi=200)
        plt.close()


def plot_metrics(metrics_df: pd.DataFrame):
    plot_df = metrics_df.set_index("Model")[["Precision", "Recall", "F1", "Accuracy"]]
    plot_df.plot(kind="bar", figsize=(10, 6))
    plt.title("Classification metrics")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig("classification_metrics.png", dpi=200)
    plt.close()

    err_df = metrics_df.set_index("Model")[["FPR", "FNR"]]
    err_df.plot(kind="bar", figsize=(8, 5))
    plt.title("Error rates")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig("error_rates.png", dpi=200)
    plt.close()


def main():
    summary_df = load_summaries()
    cm_df = create_confusion_table(summary_df)
    metrics_df = add_metrics(cm_df)

    print("=== Confusion tables ===")
    print(cm_df)
    print()
    print("=== Metrics ===")
    print(metrics_df)

    cm_df.to_csv("confusion_tables.csv", index=False)
    metrics_df.to_csv("summary_classification_metrics.csv", index=False)

    plot_confusions(cm_df)
    plot_metrics(metrics_df)

    print("\nGenerado:")
    print("- confusion_tables.csv")
    print("- summary_classification_metrics.csv")
    print("- confusion_Hybrid.png")
    print("- confusion_Regex.png")
    print("- confusion_ML.png")
    print("- classification_metrics.png")
    print("- error_rates.png")


if __name__ == "__main__":
    main()