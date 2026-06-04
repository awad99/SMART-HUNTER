"""
qwen_model_manager.py — Manages Qwen2.5-Coder-1.5B-Instruct lifecycle.

Handles:
  - Lazy model download & caching from Hugging Face
  - CUDA / CPU device auto-detection
  - Text generation with structured prompts
  - Memory management (load / unload)
"""

import gc
import os
import threading

MODEL_ID = "Qwen/Qwen2.5-Coder-7B-Instruct"
DEFAULT_MAX_NEW_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.3
DEFAULT_TOP_P = 0.9


class QwenModelManager:
    """Thread-safe singleton manager for the Qwen2.5-Coder-7B-Instruct model."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, model_id: str | None = None, force_cpu: bool = False):
        if self._initialized:
            return
        self.model_id = model_id or MODEL_ID
        self.force_cpu = force_cpu
        self._model = None
        self._tokenizer = None
        self._device = None
        self._initialized = True

    # ── Device detection ─────────────────────────────────────────────────

    @property
    def device(self) -> str:
        if self._device is not None:
            return self._device
        if self.force_cpu:
            self._device = "cpu"
            return self._device
        try:
            import torch
            if torch.cuda.is_available():
                self._device = "cuda"
                gpu_name = torch.cuda.get_device_name(0)
                gpu_mem = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
                print(f"  [+] CUDA detected: {gpu_name} ({gpu_mem:.1f} GB)")
            else:
                self._device = "cpu"
                print("  [*] No CUDA GPU found — using CPU (slower inference)")
        except ImportError:
            self._device = "cpu"
            print("  [!] PyTorch not installed — using CPU")
        return self._device

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._tokenizer is not None

    # ── Model loading ────────────────────────────────────────────────────

    def load(self) -> None:
        """Download (if needed) and load model + tokenizer into memory."""
        if self.is_loaded:
            return
        print(f"\n{'='*60}")
        print(f"  [*] Loading AI Model: {self.model_id}")
        print(f"  [*] Device: {self.device.upper()}")
        print(f"{'='*60}")

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise ImportError(
                "Required packages missing. Install with:\n"
                "  pip install transformers torch accelerate sentencepiece\n"
                f"Details: {exc}"
            ) from exc

        print("  [*] Loading tokenizer...")
        self._tokenizer = AutoTokenizer.from_pretrained(
            self.model_id,
            trust_remote_code=True,
        )

        print("  [*] Loading model weights (this may take a minute on first run)...")
        load_kwargs = {
            "trust_remote_code": True,
            "low_cpu_mem_usage": True,
        }
        if self.device == "cuda":
            load_kwargs["torch_dtype"] = torch.float16
            load_kwargs["device_map"] = "auto"
            try:
                import bitsandbytes
                load_kwargs["load_in_4bit"] = True
                print("  [+] Using 4-bit quantization")
            except ImportError:
                print("  [!] bitsandbytes not installed, skipping 4-bit quantization")
        else:
            load_kwargs["torch_dtype"] = torch.float32

        self._model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            **load_kwargs,
        )

        if self.device == "cuda" and "device_map" not in load_kwargs:
            self._model = self._model.to("cuda")

        self._model.eval()
        print(f"  [+] Model loaded successfully on {self.device.upper()}")

    # ── Text generation ──────────────────────────────────────────────────

    def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        max_new_tokens: int = DEFAULT_MAX_NEW_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
        top_p: float = DEFAULT_TOP_P,
        json_schema: dict | None = None,
    ) -> str:
        """Generate a response for the given prompt using chat template."""
        self.load()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            import torch

            text = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
            inputs = self._tokenizer(text, return_tensors="pt")

            if self.device == "cuda":
                inputs = {k: v.to("cuda") for k, v in inputs.items()}

            with torch.no_grad():
                gen_kwargs = {
                    "max_new_tokens": max_new_tokens,
                    "temperature": max(temperature, 0.01),
                    "top_p": top_p,
                    "do_sample": temperature > 0.01,
                    "pad_token_id": self._tokenizer.eos_token_id,
                }
                
                if json_schema:
                    try:
                        from lmformatenforcer import JsonSchemaParser
                        from lmformatenforcer.integrations.transformers import build_transformers_prefix_allowed_tokens_fn
                        
                        parser = JsonSchemaParser(json_schema)
                        prefix_function = build_transformers_prefix_allowed_tokens_fn(
                            self._tokenizer, parser
                        )
                        gen_kwargs["prefix_allowed_tokens_fn"] = prefix_function
                    except ImportError:
                        print("  [!] lm-format-enforcer not installed, falling back to standard generation")

                outputs = self._model.generate(
                    **inputs,
                    **gen_kwargs
                )

            # Decode only the newly generated tokens
            generated_ids = outputs[0][inputs["input_ids"].shape[1]:]
            response = self._tokenizer.decode(generated_ids, skip_special_tokens=True)
            return response.strip()

        except Exception as exc:
            print(f"  [!] Generation error: {exc}")
            return f"[ERROR] Model generation failed: {exc}"

    # ── Memory management ────────────────────────────────────────────────

    def unload(self) -> None:
        """Unload model from memory to free GPU/RAM."""
        if self._model is not None:
            del self._model
            self._model = None
        if self._tokenizer is not None:
            del self._tokenizer
            self._tokenizer = None
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except ImportError:
            pass
        gc.collect()
        print("  [*] Model unloaded from memory")

    # ── Status ───────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Return current model status."""
        info = {
            "model_id": self.model_id,
            "loaded": self.is_loaded,
            "device": self.device or "not_detected",
        }
        if self.is_loaded and self.device == "cuda":
            try:
                import torch
                info["gpu_memory_allocated_mb"] = round(
                    torch.cuda.memory_allocated() / (1024 ** 2), 1
                )
                info["gpu_memory_reserved_mb"] = round(
                    torch.cuda.memory_reserved() / (1024 ** 2), 1
                )
            except Exception:
                pass
        return info
