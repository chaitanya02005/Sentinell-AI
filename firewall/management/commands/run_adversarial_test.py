"""
firewall/management/commands/run_adversarial_test.py
====================================================
Django management command that loads 300 adversarial prompts from the
HackAPrompt HuggingFace dataset (via streaming) and runs each one through
the full Sentinell.AI security pipeline:

    scan() → apply_policy() → calculate_risk()

Usage:
    python manage.py run_adversarial_test
    python manage.py run_adversarial_test --count 100    # custom count
    python manage.py run_adversarial_test --role ADMIN   # change role
"""

from django.core.management.base import BaseCommand

from firewall.load_hackaprompt import load_adversarial_prompts
from firewall.scanner import scan
from firewall.policy_engine import apply_policy, ALLOW, BLOCK, TOKENIZE
from firewall.risk_scorer import calculate_risk


class Command(BaseCommand):
    help = (
        "Load adversarial prompts from the HackAPrompt HuggingFace dataset "
        "(streaming, no full download) and run them through the Sentinell.AI "
        "scan → policy → risk pipeline. Prints a summary report."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--count",
            type=int,
            default=300,
            help="Number of prompts to load from the dataset (default: 300).",
        )
        parser.add_argument(
            "--role",
            type=str,
            default="INTERN",
            choices=["ADMIN", "EMPLOYEE", "INTERN"],
            help="Role to evaluate policy against (default: INTERN — most restrictive).",
        )
        parser.add_argument(
            "--token",
            type=str,
            default=None,
            help=(
                "HuggingFace API token for gated dataset access. "
                "If not set here, reads from the HF_TOKEN environment variable. "
                "Get yours at https://huggingface.co/settings/tokens"
            ),
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Print per-prompt results in addition to the summary.",
        )

    def handle(self, *args, **options):
        count = options["count"]
        role = options["role"]
        verbose = options["verbose"]
        token = options.get("token")

        self.stdout.write(self.style.MIGRATE_HEADING(
            f"\n{'=' * 60}\n"
            f"  Sentinell.AI — HackAPrompt Adversarial Test\n"
            f"  Prompts: {count}  |  Role: {role}\n"
            f"{'=' * 60}\n"
        ))

        # ── Step 1: Load adversarial prompts ─────────────────────────────
        self.stdout.write("Loading adversarial prompts from HuggingFace (streaming)...")
        adversarial_prompts = load_adversarial_prompts(count, token=token)
        self.stdout.write(self.style.SUCCESS(
            f"✓ {len(adversarial_prompts)} prompts collected.\n"
        ))

        # ── Step 2: Run each prompt through the pipeline ─────────────────
        results = {ALLOW: 0, TOKENIZE: 0, BLOCK: 0}
        risk_total = 0

        for i, prompt in enumerate(adversarial_prompts, start=1):
            detections = scan(prompt)
            policy = apply_policy(role, detections)
            action = policy["action"]

            risk = calculate_risk(role, detections)
            risk_score = risk["score"]

            # Defense-in-depth: high risk score upgrades ALLOW → BLOCK
            if risk["should_block"] and action == ALLOW:
                action = BLOCK

            results[action] = results.get(action, 0) + 1
            risk_total += risk_score

            if verbose:
                preview = prompt[:80].replace("\n", " ")
                dtypes = ", ".join({d.dtype for d in detections}) or "none"
                self.stdout.write(
                    f"[{i:>3}] {action:<8}  risk={risk_score:>3}%  "
                    f"types=[{dtypes}]  prompt={preview!r}"
                )

        # ── Step 3: Print summary report ─────────────────────────────────
        total = len(adversarial_prompts)
        avg_risk = risk_total / total if total else 0

        self.stdout.write(self.style.MIGRATE_HEADING(
            f"\n{'=' * 60}\n"
            f"  RESULTS SUMMARY  (role={role}, n={total})\n"
            f"{'=' * 60}"
        ))
        self.stdout.write(
            f"  {'Action':<12} {'Count':>6}  {'% of total':>10}"
        )
        self.stdout.write(f"  {'-' * 32}")

        for action_label, result_count in [
            (BLOCK,    results.get(BLOCK, 0)),
            (TOKENIZE, results.get(TOKENIZE, 0)),
            (ALLOW,    results.get(ALLOW, 0)),
        ]:
            pct = (result_count / total * 100) if total else 0
            style_fn = (
                self.style.ERROR   if action_label == BLOCK    else
                self.style.WARNING if action_label == TOKENIZE else
                self.style.SUCCESS
            )
            self.stdout.write(style_fn(
                f"  {action_label:<12} {result_count:>6}  {pct:>9.1f}%"
            ))

        self.stdout.write(f"  {'-' * 32}")
        self.stdout.write(f"  {'TOTAL':<12} {total:>6}  {'100.0':>9}%")
        self.stdout.write(
            f"\n  Average risk score : {avg_risk:.1f}%"
        )
        self.stdout.write(self.style.MIGRATE_HEADING(
            f"{'=' * 60}\n"
        ))
