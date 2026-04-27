from pathlib import Path

import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer


class ONNXThreatScorer:
    def __init__(self, model_dir):
        self.model_dir = Path(model_dir)
        self.model_name = self.model_dir.name
        self.ready = False

        if not self.model_dir.exists():
            raise FileNotFoundError(f"Model directory not found: {self.model_dir}")

        self.onnx_path = self._find_onnx_file(self.model_dir)
        if self.onnx_path is None:
            raise FileNotFoundError(f"No .onnx file found inside: {self.model_dir}")

        self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_dir))
        self.session = ort.InferenceSession(
            str(self.onnx_path),
            providers=["CPUExecutionProvider"]
        )

        self.input_names = [item.name for item in self.session.get_inputs()]
        self.pattern_cache = {}
        self.ready = True

    def _find_onnx_file(self, directory: Path):
        candidates = list(directory.rglob("*.onnx"))
        if not candidates:
            return None
        candidates.sort()
        return candidates[0]

    def _mean_pool(self, output_array):
        arr = np.array(output_array)

        if arr.ndim == 3:
            return arr.mean(axis=1)[0]

        if arr.ndim == 2:
            return arr[0]

        return arr.reshape(-1)

    def _normalize(self, vector):
        vector = np.array(vector, dtype=np.float32)
        norm = np.linalg.norm(vector)
        if norm == 0:
            return vector
        return vector / norm

    def encode_text(self, text: str):
        encoded = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=128,
            return_tensors="np"
        )

        ort_inputs = {}
        for name in self.input_names:
            if name in encoded:
                ort_inputs[name] = encoded[name]
            elif name == "token_type_ids":
                ort_inputs[name] = np.zeros_like(encoded["input_ids"], dtype=np.int64)

        outputs = self.session.run(None, ort_inputs)
        embedding = self._mean_pool(outputs[0])
        return self._normalize(embedding)

    def _pattern_embedding(self, pattern: str):
        if pattern not in self.pattern_cache:
            self.pattern_cache[pattern] = self.encode_text(pattern)
        return self.pattern_cache[pattern]

    def cosine_similarity(self, a, b):
        return float(np.dot(a, b))

    def score_text(self, text: str, patterns: list[str]):
        text_emb = self.encode_text(text)

        best_score = -1.0
        best_pattern = None

        for pattern in patterns:
            pat_emb = self._pattern_embedding(pattern)
            score = self.cosine_similarity(text_emb, pat_emb)
            if score > best_score:
                best_score = score
                best_pattern = pattern

        return best_score, best_pattern
