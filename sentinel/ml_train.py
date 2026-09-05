from pathlib import Path
import pickle
from sklearn.ensemble import IsolationForest

MODEL_PATH = Path(__file__).resolve().parent / "model.pkl"


def train(normal_feature_rows: list[list[float]]) -> None:
    model = IsolationForest(random_state=42, contamination="auto", n_estimators=100)
    model.fit(normal_feature_rows)
    with MODEL_PATH.open("wb") as stream:
        pickle.dump(model, stream)


if __name__ == "__main__":
    train([[10, 3, 0, 2, 500, 100, 0, 60], [12, 4, 0, 2, 520, 110, 0, 70]])
    print(f"Wrote {MODEL_PATH}")
