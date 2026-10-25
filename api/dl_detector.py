import os
import joblib
import numpy as np

DL_MODEL_PATH = os.path.join(os.path.dirname(__file__), "dl_model.pt")
DL_WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "dl_weights.joblib")
MAX_SEQ_LEN = 192

# Try PyTorch import; if unavailable (e.g. Vercel Serverless 250MB limit), fallback to NumPy engine
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    class CharCNNBiGRU(nn.Module):
        def __init__(self, vocab_size=130, embed_dim=48, hidden_dim=64):
            super().__init__()
            self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
            self.conv3 = nn.Conv1d(embed_dim, 48, kernel_size=3, padding=1)
            self.conv5 = nn.Conv1d(embed_dim, 48, kernel_size=5, padding=2)
            self.gru = nn.GRU(96, hidden_dim, batch_first=True, bidirectional=True)
            self.dropout = nn.Dropout(0.3)
            self.fc1 = nn.Linear(hidden_dim * 2, 64)
            self.fc2 = nn.Linear(64, 1)

        def forward(self, x):
            emb = self.embedding(x)
            emb_t = emb.transpose(1, 2)
            c3 = F.relu(self.conv3(emb_t))
            c5 = F.relu(self.conv5(emb_t))
            conv_out = torch.cat([c3, c5], dim=1).transpose(1, 2)
            gru_out, _ = self.gru(conv_out)
            pooled = torch.max(gru_out, dim=1)[0]
            feat = self.dropout(F.relu(self.fc1(pooled)))
            out = torch.sigmoid(self.fc2(feat))
            return out.squeeze(-1)
except Exception:
    torch = None

_CACHED_TORCH_MODEL = None
_CACHED_NUMPY_WEIGHTS = None

def get_dl_model():
    global _CACHED_TORCH_MODEL
    if torch is None:
        return None
    if _CACHED_TORCH_MODEL is not None:
        return _CACHED_TORCH_MODEL
    if os.path.exists(DL_MODEL_PATH):
        try:
            model = CharCNNBiGRU()
            model.load_state_dict(torch.load(DL_MODEL_PATH, map_location=torch.device("cpu")))
            model.eval()
            _CACHED_TORCH_MODEL = model
            return _CACHED_TORCH_MODEL
        except Exception:
            return None
    return None

def get_numpy_weights():
    global _CACHED_NUMPY_WEIGHTS
    if _CACHED_NUMPY_WEIGHTS is not None:
        return _CACHED_NUMPY_WEIGHTS
    if os.path.exists(DL_WEIGHTS_PATH):
        try:
            _CACHED_NUMPY_WEIGHTS = joblib.load(DL_WEIGHTS_PATH)
            return _CACHED_NUMPY_WEIGHTS
        except Exception:
            return None
    return None

def _sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -25.0, 25.0)))

def _relu(x):
    return np.maximum(0.0, x)

def _numpy_dl_forward(url: str, w: dict) -> float:
    clean = url.strip()[:MAX_SEQ_LEN]
    indices = [ord(c) - 31 if 32 <= ord(c) <= 126 else 128 for c in clean]
    if len(indices) < MAX_SEQ_LEN:
        indices += [0] * (MAX_SEQ_LEN - len(indices))

    # 1. Embedding
    emb = w['embedding.weight'][indices] # (192, 48)

    # 2. Conv1D k=3 (out_ch=48, in_ch=48, k=3), pad=1
    x_in = emb.T # (48, 192)
    x_pad3 = np.pad(x_in, ((0, 0), (1, 1)), mode='constant')
    c3 = np.zeros((48, MAX_SEQ_LEN))
    w3, b3 = w['conv3.weight'], w['conv3.bias']
    for i in range(MAX_SEQ_LEN):
        patch = x_pad3[:, i:i+3]
        c3[:, i] = np.sum(w3 * patch, axis=(1, 2)) + b3
    c3 = _relu(c3)

    # 3. Conv1D k=5 (out_ch=48, in_ch=48, k=5), pad=2
    x_pad5 = np.pad(x_in, ((0, 0), (2, 2)), mode='constant')
    c5 = np.zeros((48, MAX_SEQ_LEN))
    w5, b5 = w['conv5.weight'], w['conv5.bias']
    for i in range(MAX_SEQ_LEN):
        patch = x_pad5[:, i:i+5]
        c5[:, i] = np.sum(w5 * patch, axis=(1, 2)) + b5
    c5 = _relu(c5)

    conv_out = np.vstack([c3, c5]).T # (192, 96)

    # 4. Bidirectional GRU
    def _run_gru(x_seq, w_ih, w_hh, b_ih, b_hh):
        h = np.zeros(64)
        h_all = []
        for xt in x_seq:
            gi = xt @ w_ih.T + b_ih
            gh = h @ w_hh.T + b_hh
            r = _sigmoid(gi[:64] + gh[:64])
            z = _sigmoid(gi[64:128] + gh[64:128])
            n = np.tanh(gi[128:] + r * gh[128:])
            h = (1.0 - z) * n + z * h
            h_all.append(h)
        return np.array(h_all)

    fwd_h = _run_gru(conv_out, w['gru.weight_ih_l0'], w['gru.weight_hh_l0'], w['gru.bias_ih_l0'], w['gru.bias_hh_l0'])
    bwd_h = _run_gru(conv_out[::-1], w['gru.weight_ih_l0_reverse'], w['gru.weight_hh_l0_reverse'], w['gru.bias_ih_l0_reverse'], w['gru.bias_hh_l0_reverse'])[::-1]

    bi_h = np.concatenate([fwd_h, bwd_h], axis=-1)
    pooled = np.max(bi_h, axis=0)

    # 5. Dense FC layers
    fc1_out = _relu(pooled @ w['fc1.weight'].T + w['fc1.bias'])
    out = _sigmoid(fc1_out @ w['fc2.weight'].T + w['fc2.bias'])
    return float(out[0])

def url_to_tensor(url: str, max_len: int = MAX_SEQ_LEN):
    clean_url = url.strip()[:max_len]
    indices = []
    for ch in clean_url:
        code = ord(ch)
        if 32 <= code <= 126:
            indices.append(code - 31)
        else:
            indices.append(128)
    if len(indices) < max_len:
        indices += [0] * (max_len - len(indices))
    return torch.tensor([indices], dtype=torch.long)

def predict_dl(url: str) -> dict:
    # 1. Try PyTorch native
    torch_model = get_dl_model()
    prob = None
    engine_name = "Character-level 1D-CNN + BiGRU (PyTorch)"

    if torch_model is not None:
        try:
            x = url_to_tensor(url)
            with torch.no_grad():
                output = torch_model(x)
                prob = float(output[0].item())
        except Exception:
            prob = None

    # 2. Try NumPy lightweight forward pass
    if prob is None:
        weights = get_numpy_weights()
        if weights is not None:
            try:
                prob = _numpy_dl_forward(url, weights)
                engine_name = "Character-level 1D-CNN + BiGRU (Neural Inference Engine)"
            except Exception:
                prob = None

    if prob is None:
        return {
            "available": False,
            "status": "not_trained",
            "score_percent": 0.0,
            "prediction": "unknown",
            "architecture": "Character-level 1D-CNN + BiGRU Neural Network",
            "details": "Deep Learning model weights not found. Run training script to compile weights.",
            "hotspot_tokens": []
        }

    prob_percent = round(prob * 100, 1)
    prediction_str = "suspicious" if prob_percent >= 50.0 else "benign"

    hotspot_tokens = []
    lowered = url.lower()
    phish_keywords = ["login", "verify", "secure", "bank", "account", "update", "wallet", "free", "gift", "bonus", "discount", "confirm", "claim", "auth", "checkout"]
    for kw in phish_keywords:
        if kw in lowered:
            hotspot_tokens.append(kw)

    return {
        "available": True,
        "status": "active",
        "score_percent": prob_percent,
        "prediction": prediction_str,
        "architecture": engine_name,
        "details": f"Deep neural network assessed URL character sequence with {prob_percent}% phishing probability.",
        "hotspot_tokens": hotspot_tokens
    }
