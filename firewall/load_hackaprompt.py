"""
firewall/load_hackaprompt.py
============================
Loads 300 adversarial prompts from the HackAPrompt dataset on HuggingFace
using streaming mode — the full dataset is never downloaded.

NOTE: The hackaprompt/hackaprompt-dataset is a *gated* dataset on HuggingFace.
You must accept its terms at https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset
and then set your HuggingFace token before using this module:

    export HF_TOKEN="hf_your_token_here"

Or pass the token directly:
    prompts = load_adversarial_prompts(token="hf_your_token_here")

Usage (standalone):
    from firewall.load_hackaprompt import load_adversarial_prompts
    adversarial_prompts = load_adversarial_prompts()   # returns list of 300 str

Dataset:
    https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset
"""

import itertools
import os


def load_adversarial_prompts(n: int = 300, token=None) -> list:
    """
    Stream the HackAPrompt dataset from HuggingFace and return the first *n*
    non-empty prompts as a plain Python list.

    Parameters
    ----------
    n : int
        Maximum number of prompts to collect (default: 300).
    token : str, optional
        HuggingFace API token. If None, reads from the HF_TOKEN environment
        variable. Required because the dataset is gated.

    Returns
    -------
    adversarial_prompts : list[str]
        A list of up to *n* adversarial prompt strings.
    """
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise ImportError(
            "The 'datasets' library is required. "
            "Install it with:  pip install 'datasets>=2.14'"
        ) from exc

    # ── Resolve authentication token ─────────────────────────────────────
    hf_token = token or os.environ.get("HF_TOKEN")
    if not hf_token:
        raise EnvironmentError(
            "\n\n[HackAPrompt] HuggingFace authentication required.\n"
            "The 'hackaprompt/hackaprompt-dataset' is a gated dataset.\n\n"
            "Steps to fix:\n"
            "  1. Accept the dataset terms at:\n"
            "     https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset\n"
            "  2. Get your HuggingFace token from:\n"
            "     https://huggingface.co/settings/tokens\n"
            "  3. Set the environment variable before running:\n"
            "     export HF_TOKEN='hf_your_token_here'\n"
            "  Or pass it directly:\n"
            "     load_adversarial_prompts(token='hf_your_token_here')\n"
        )

    # ── Load in streaming mode – nothing is downloaded past what we read ──
    print(f"[HackAPrompt] Connecting to HuggingFace (streaming mode)...")
    dataset = load_dataset(
        "hackaprompt/hackaprompt-dataset",
        split="train",
        streaming=True,
        token=hf_token,
        trust_remote_code=False,
    )

    # ── Collect exactly n prompts, then stop ─────────────────────────────
    adversarial_prompts: list = []
    for row in itertools.islice(dataset, n):
        prompt_text = row.get("prompt", "")
        if prompt_text:                     # skip empty / null rows
            adversarial_prompts.append(prompt_text)
        if len(adversarial_prompts) >= n:   # hard stop at n
            break

    print(f"[HackAPrompt] Collected {len(adversarial_prompts)} adversarial prompts.")
    return adversarial_prompts


# ── Allow running as a quick smoke-test ───────────────────────────────────────
if __name__ == "__main__":
    prompts = load_adversarial_prompts(300)
    print(f"First prompt preview: {prompts[0][:120]!r}" if prompts else "No prompts loaded.")
