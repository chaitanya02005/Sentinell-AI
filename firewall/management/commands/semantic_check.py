import json

from django.core.management.base import BaseCommand, CommandError

from firewall.agents.semantic_agent import SemanticSecurityAgent
from firewall.scanner import scan


class Command(BaseCommand):
    help = "Run one prompt through the semantic security agent and print its evidence."

    def add_arguments(self, parser):
        parser.add_argument("prompt", nargs="+", help="Prompt text to classify.")

    def handle(self, *args, **options):
        prompt = " ".join(options["prompt"]).strip()
        if not prompt:
            raise CommandError("Prompt text is required.")

        report = SemanticSecurityAgent().run(
            prompt=prompt,
            detections=scan(prompt),
        )
        self.stdout.write(json.dumps(report, indent=2, sort_keys=True))
