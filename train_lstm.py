"""Train and export MalShot's byte-sequence LSTM model.

Example:
    python train_lstm.py --clean-dir data/clean --malware-dir data/malware \
        --output lstm_malware.onnx --epochs 10

The exported ONNX input shape is [batch, 4096], matching the deep
inspection contract used by the Go runtime.
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path
from typing import Iterable, Sequence

import torch
from torch import nn
from torch.utils.data import Dataset, DataLoader


SEQUENCE_LENGTH = 4096


class BinaryWindowDataset(Dataset[tuple[torch.Tensor, torch.Tensor]]):
    """Reads binary files and returns normalized padded byte windows."""

    def __init__(
        self,
        files: Sequence[tuple[Path, int]],
        sequence_length: int = SEQUENCE_LENGTH,
    ) -> None:
        self.files = list(files)
        self.sequence_length = sequence_length

    def __len__(self) -> int:
        return len(self.files)

    def __getitem__(self, index: int) -> tuple[torch.Tensor, torch.Tensor]:
        path, label = self.files[index]
        with path.open("rb") as source:
            data = source.read(self.sequence_length)
        values = torch.zeros(self.sequence_length, dtype=torch.float32)
        if data:
            values[: len(data)] = torch.tensor(list(data), dtype=torch.float32) / 255.0
        return values, torch.tensor([label], dtype=torch.float32)


class MalwareLSTM(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=1,
            hidden_size=64,
            num_layers=2,
            batch_first=True,
            dropout=0.2,
        )
        self.hidden = nn.Sequential(nn.Linear(64, 16), nn.ReLU())
        self.output = nn.Sequential(nn.Linear(16, 1), nn.Sigmoid())

    def forward(self, values: torch.Tensor) -> torch.Tensor:
        if values.dim() == 2:
            values = values.unsqueeze(-1)
        sequence, _ = self.lstm(values)
        return self.output(self.hidden(sequence[:, -1, :]))


def collect_files(directory: Path, label: int) -> list[tuple[Path, int]]:
    if not directory.is_dir():
        raise FileNotFoundError(f"training directory does not exist: {directory}")
    return [(path, label) for path in directory.rglob("*") if path.is_file()]


def split_records(records: list[tuple[Path, int]], validation_ratio: float) -> tuple[list, list]:
    random.shuffle(records)
    validation_count = max(1, int(len(records) * validation_ratio)) if records else 0
    return records[validation_count:], records[:validation_count]


def evaluate(model: nn.Module, loader: DataLoader, device: torch.device) -> float:
    model.eval()
    loss_fn = nn.BCELoss()
    total = 0.0
    count = 0
    with torch.no_grad():
        for values, labels in loader:
            loss = loss_fn(model(values.to(device)), labels.to(device))
            total += float(loss) * len(values)
            count += len(values)
    return total / count if count else 0.0


def train(args: argparse.Namespace) -> None:
    random.seed(args.seed)
    torch.manual_seed(args.seed)
    records = collect_files(Path(args.clean_dir), 0) + collect_files(Path(args.malware_dir), 1)
    if len(records) < 2:
        raise ValueError("at least two training files are required")
    training, validation = split_records(records, args.validation_ratio)
    device = torch.device("cuda" if args.cuda and torch.cuda.is_available() else "cpu")
    train_loader = DataLoader(BinaryWindowDataset(training), batch_size=args.batch_size, shuffle=True)
    validation_loader = DataLoader(BinaryWindowDataset(validation), batch_size=args.batch_size)
    model = MalwareLSTM().to(device)
    loss_fn = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)
    for epoch in range(args.epochs):
        model.train()
        for values, labels in train_loader:
            optimizer.zero_grad()
            loss = loss_fn(model(values.to(device)), labels.to(device))
            loss.backward()
            optimizer.step()
        validation_loss = evaluate(model, validation_loader, device)
        print(f"epoch={epoch + 1}/{args.epochs} validation_loss={validation_loss:.6f}")

    model.eval()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    example = torch.zeros(1, SEQUENCE_LENGTH, dtype=torch.float32, device=device)
    torch.onnx.export(
        model,
        example,
        output,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={"input": {0: "batch"}, "output": {0: "batch"}},
        opset_version=17,
    )
    print(f"exported={output} device={device}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean-dir", required=True)
    parser.add_argument("--malware-dir", required=True)
    parser.add_argument("--output", default="lstm_malware.onnx")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--validation-ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cuda", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    train(parse_args())
