import os
import numpy as np
import torch
from transformers import (
    AutoFeatureExtractor,
    AutoModelForAudioClassification,
)


class HuggingFaceVoiceDetector:
    """
    Pre-trained deepfake audio detection model
    Singleton pattern - model sirf ek baar load hota hai
    """

    _instance = None
    _model = None
    _feature_extractor = None
    _device = None

    # Best model for production (96%+ accuracy)
    MODEL_NAME = "MelodyMachine/Deepfake-audio-detection-V2"
    
    # Fallback agar primary fail ho
    FALLBACK_MODEL = "motheecreator/Deepfake-audio-detection"

    def __new__(cls):
        """Singleton - ek hi instance banega"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Model load karo (server start hone par sirf 1 baar)"""
        self._device = torch.device("cpu")  # Render pe CPU only
        
        # Set thread count for better CPU performance
        torch.set_num_threads(2)
        
        print("🔄 Loading HuggingFace deepfake detection model...")
        
        try:
            self._load_model(self.MODEL_NAME)
            print(f"✅ Loaded: {self.MODEL_NAME}")
        except Exception as e:
            print(f"⚠️ Primary model failed: {e}")
            print(f"🔄 Trying fallback: {self.FALLBACK_MODEL}")
            try:
                self._load_model(self.FALLBACK_MODEL)
                print(f"✅ Loaded fallback: {self.FALLBACK_MODEL}")
            except Exception as e2:
                print(f"❌ Both models failed: {e2}")
                self._model = None
                self._feature_extractor = None

    def _load_model(self, model_name: str):
        """Specific model load karo"""
        # Cache directory (Render mein persistent storage ke liye)
        cache_dir = os.environ.get("HF_HOME", "/tmp/hf_cache")
        os.makedirs(cache_dir, exist_ok=True)

        self._feature_extractor = AutoFeatureExtractor.from_pretrained(
            model_name,
            cache_dir=cache_dir,
        )
        
        self._model = AutoModelForAudioClassification.from_pretrained(
            model_name,
            cache_dir=cache_dir,
        )
        self._model.to(self._device)
        self._model.eval()  # Inference mode

    def is_loaded(self) -> bool:
        """Check karo model loaded hai ya nahi"""
        return self._model is not None and self._feature_extractor is not None

    def predict(self, audio: np.ndarray, sample_rate: int) -> dict:
        """
        Audio analyze karo aur AI probability return karo
        
        Returns:
            {
                "ai_probability": 0.0 to 1.0,
                "human_probability": 0.0 to 1.0,
                "is_ai": bool,
                "model_confidence": float,
                "raw_label": str,
            }
        """
        if not self.is_loaded():
            return {
                "ai_probability": 0.5,
                "human_probability": 0.5,
                "is_ai": False,
                "model_confidence": 0.0,
                "raw_label": "model_not_loaded",
                "error": "Model not loaded"
            }

        try:
            # Resample to 16kHz if needed (model requirement)
            if sample_rate != 16000:
                import librosa
                audio = librosa.resample(
                    audio, orig_sr=sample_rate, target_sr=16000
                )
                sample_rate = 16000

            # Audio length limit (30 seconds max for memory)
            max_samples = 30 * sample_rate
            if len(audio) > max_samples:
                # Multiple chunks ka average lo (better accuracy for long audio)
                return self._predict_chunked(audio, sample_rate, max_samples)

            # Single prediction
            return self._predict_single(audio, sample_rate)

        except Exception as e:
            print(f"❌ HF prediction error: {e}")
            return {
                "ai_probability": 0.5,
                "human_probability": 0.5,
                "is_ai": False,
                "model_confidence": 0.0,
                "raw_label": "error",
                "error": str(e)
            }

    def _predict_single(self, audio: np.ndarray, sr: int) -> dict:
        """Single audio chunk pe prediction"""
        # Preprocess
        inputs = self._feature_extractor(
            audio,
            sampling_rate=sr,
            return_tensors="pt",
            padding=True,
        )
        inputs = {k: v.to(self._device) for k, v in inputs.items()}

        # Inference (no gradient tracking = faster + less RAM)
        with torch.no_grad():
            outputs = self._model(**inputs)
            logits = outputs.logits
            probs = torch.nn.functional.softmax(logits, dim=-1)[0]

        # Get labels from model config
        id2label = self._model.config.id2label
        
        # Find AI/fake probability
        ai_prob = 0.0
        human_prob = 0.0
        raw_label = ""

        for idx, prob in enumerate(probs):
            label = id2label[idx].lower()
            prob_value = float(prob.item())

            if any(keyword in label for keyword in ["fake", "spoof", "ai", "synthetic", "deepfake"]):
                ai_prob = max(ai_prob, prob_value)
            elif any(keyword in label for keyword in ["real", "human", "bonafide", "genuine"]):
                human_prob = max(human_prob, prob_value)

        # Edge case: if labels don't match standard naming
        if ai_prob == 0.0 and human_prob == 0.0:
            # Take highest probability as the answer
            max_idx = torch.argmax(probs).item()
            raw_label = id2label[max_idx]
            
            # Assume binary classification: idx 0 = real, idx 1 = fake (most common)
            if len(probs) == 2:
                human_prob = float(probs[0].item())
                ai_prob = float(probs[1].item())
            else:
                ai_prob = float(probs[max_idx].item())
                human_prob = 1.0 - ai_prob
        else:
            max_idx = torch.argmax(probs).item()
            raw_label = id2label[max_idx]

        # Normalize (sometimes don't sum to 1)
        total = ai_prob + human_prob
        if total > 0:
            ai_prob = ai_prob / total
            human_prob = human_prob / total

        return {
            "ai_probability": round(ai_prob, 4),
            "human_probability": round(human_prob, 4),
            "is_ai": ai_prob >= 0.5,
            "model_confidence": round(abs(ai_prob - 0.5) * 2, 4),
            "raw_label": raw_label,
        }

    def _predict_chunked(
        self, audio: np.ndarray, sr: int, chunk_size: int
    ) -> dict:
        """
        Long audio ke liye chunks mein todke average lo
        Better accuracy for long recordings
        """
        chunks = []
        
        # 30-second chunks with 5-sec overlap
        overlap = 5 * sr
        step = chunk_size - overlap
        
        for start in range(0, len(audio), step):
            end = min(start + chunk_size, len(audio))
            chunk = audio[start:end]
            
            # Skip very short chunks
            if len(chunk) < sr * 2:  # Less than 2 sec
                continue
                
            chunks.append(chunk)
            
            # Limit max chunks (memory safety)
            if len(chunks) >= 5:
                break

        # Predict on each chunk
        ai_probs = []
        human_probs = []
        confidences = []
        last_label = ""

        for chunk in chunks:
            result = self._predict_single(chunk, sr)
            ai_probs.append(result["ai_probability"])
            human_probs.append(result["human_probability"])
            confidences.append(result["model_confidence"])
            last_label = result["raw_label"]

        # Weighted average (higher confidence = more weight)
        if confidences and sum(confidences) > 0:
            weights = np.array(confidences)
            weights = weights / weights.sum()
            avg_ai = float(np.average(ai_probs, weights=weights))
            avg_human = float(np.average(human_probs, weights=weights))
        else:
            avg_ai = float(np.mean(ai_probs)) if ai_probs else 0.5
            avg_human = float(np.mean(human_probs)) if human_probs else 0.5

        return {
            "ai_probability": round(avg_ai, 4),
            "human_probability": round(avg_human, 4),
            "is_ai": avg_ai >= 0.5,
            "model_confidence": round(abs(avg_ai - 0.5) * 2, 4),
            "raw_label": last_label,
            "chunks_analyzed": len(chunks),
        }
