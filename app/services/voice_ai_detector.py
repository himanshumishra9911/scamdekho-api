"""
Voice AI Detector - 3 Layer Detection System
Layer 1: HuggingFace pre-trained model (60% weight) - Primary
Layer 2: Feature-based analysis (25% weight) - Backup
Layer 3: Heuristic rules (15% weight) - Edge cases
"""
import numpy as np
from app.services.voice_hf_model import HuggingFaceVoiceDetector


class VoiceAIDetector:
    """
    High-accuracy 3-layer detection system
    Target accuracy: 95%+
    """

    def __init__(self):
        # HF model singleton - loads once, reused forever
        self.hf_detector = HuggingFaceVoiceDetector()

    def detect(
        self, audio: np.ndarray, sample_rate: int, features: dict
    ) -> dict:
        """
        Multi-layer detection with weighted combination
        """
        scores = []
        weights = []
        layer_results = {}

        # ─────── Layer 1: HuggingFace Model (60%) ───────
        hf_result = self.hf_detector.predict(audio, sample_rate)
        layer_results["hf_model"] = hf_result
        
        if hf_result.get("error"):
            print(f"⚠️ HF model error, using features only")
            # If HF failed, increase weight of feature-based
            scores.append(self._feature_based_score(features))
            weights.append(0.70)
            scores.append(self._heuristic_score(features))
            weights.append(0.30)
        else:
            # All 3 layers active
            scores.append(hf_result["ai_probability"])
            weights.append(0.60)
            
            scores.append(self._feature_based_score(features))
            weights.append(0.25)
            
            scores.append(self._heuristic_score(features))
            weights.append(0.15)

        # ─────── Weighted combination ───────
        total_weight = sum(weights)
        ai_probability = sum(s * w for s, w in zip(scores, weights)) / total_weight
        ai_probability = float(np.clip(ai_probability, 0.0, 1.0))

        is_ai = ai_probability >= 0.5
        confidence = abs(ai_probability - 0.5) * 2

        # Layer-wise breakdown (for transparency)
        layer_results["feature_based"] = {
            "ai_probability": round(self._feature_based_score(features), 4)
        }
        layer_results["heuristic"] = {
            "ai_probability": round(self._heuristic_score(features), 4)
        }

        return {
            "is_ai_generated": bool(is_ai),
            "ai_probability": round(ai_probability, 4),
            "human_probability": round(1 - ai_probability, 4),
            "confidence": round(confidence, 4),
            "layer_breakdown": layer_results,
            "detection_method": "3-layer ensemble" if not hf_result.get("error") else "feature-based fallback"
        }

    def _feature_based_score(self, features: dict) -> float:
        """Layer 2: Feature thresholds"""
        signals = []

        mfcc_var = features["mfcc"]["mfcc_variance"]
        if mfcc_var < 50:
            signals.append(0.85)
        elif mfcc_var < 100:
            signals.append(0.55)
        else:
            signals.append(0.20)

        smoothness = features["mfcc"]["smoothness_ratio"]
        if smoothness < 0.10:
            signals.append(0.80)
        elif smoothness < 0.20:
            signals.append(0.50)
        else:
            signals.append(0.20)

        pitch_var = features["prosody"]["pitch_variation"]
        if pitch_var < 0.05:
            signals.append(0.90)
        elif pitch_var < 0.15:
            signals.append(0.50)
        else:
            signals.append(0.15)

        jitter = features["naturalness"]["jitter"]
        if jitter < 0.005:
            signals.append(0.85)
        elif jitter < 0.02:
            signals.append(0.45)
        else:
            signals.append(0.15)

        shimmer = features["naturalness"]["shimmer"]
        if shimmer < 0.01:
            signals.append(0.80)
        elif shimmer < 0.05:
            signals.append(0.40)
        else:
            signals.append(0.15)

        freq_cutoff = features["artifacts"]["freq_cutoff_ratio"]
        if freq_cutoff < 0.02:
            signals.append(0.85)
        elif freq_cutoff < 0.10:
            signals.append(0.45)
        else:
            signals.append(0.20)

        cent_var = features["spectral"]["centroid_variation"]
        if cent_var < 0.10:
            signals.append(0.70)
        elif cent_var < 0.30:
            signals.append(0.40)
        else:
            signals.append(0.15)

        return float(np.mean(signals))

    def _heuristic_score(self, features: dict) -> float:
        """Layer 3: Red flag rules"""
        red_flags = 0
        total = 7

        if features["prosody"]["pitch_variation"] < 0.08:
            red_flags += 1
        if features["prosody"]["pause_ratio"] < 0.05:
            red_flags += 1
        if features["mfcc"]["mfcc_variance"] < 60:
            red_flags += 1
        if features["naturalness"]["micro_variation_score"] < 0.01:
            red_flags += 1
        if features["artifacts"]["freq_cutoff_ratio"] < 0.02:
            red_flags += 1
        if features["naturalness"]["jitter"] < 0.005:
            red_flags += 1
        if features["mfcc"]["smoothness_ratio"] < 0.10:
            red_flags += 1

        return red_flags / total

    def get_red_flags(self, features: dict, hf_result: dict = None) -> list:
        """User-facing red flags"""
        flags = []

        # HF model based flag (highest priority)
        if hf_result and hf_result.get("ai_probability", 0) > 0.8:
            flags.append({
                "flag": "AI Model Detection",
                "severity": "critical",
                "description": f"Pre-trained deepfake detection model identified this voice as AI-generated with {hf_result['ai_probability']*100:.1f}% confidence."
            })

        if features["naturalness"]["jitter"] < 0.005:
            flags.append({
                "flag": "Missing Micro-Pitch Variations",
                "severity": "high",
                "description": "Voice lacks natural pitch micro-variations (jitter) found in human speech."
            })

        if features["naturalness"]["shimmer"] < 0.01:
            flags.append({
                "flag": "Missing Amplitude Variations",
                "severity": "medium",
                "description": "Voice amplitude is unnaturally consistent."
            })

        if features["artifacts"]["freq_cutoff_ratio"] < 0.02:
            flags.append({
                "flag": "Frequency Cutoff Detected",
                "severity": "high",
                "description": "Sharp frequency cutoff detected, common in AI-generated speech."
            })

        if features["prosody"]["pitch_variation"] < 0.05:
            flags.append({
                "flag": "Monotone Speech Pattern",
                "severity": "high",
                "description": "Voice pitch is unusually flat, lacking natural intonation."
            })

        if features["mfcc"]["mfcc_variance"] < 50:
            flags.append({
                "flag": "Over-Smooth Voice Pattern",
                "severity": "medium",
                "description": "Voice spectral pattern is unusually smooth (typical AI artifact)."
            })

        if features["prosody"]["pause_ratio"] < 0.03:
            flags.append({
                "flag": "No Natural Breathing Pauses",
                "severity": "medium",
                "description": "Audio lacks natural breathing pauses found in human speech."
            })

        return flags
