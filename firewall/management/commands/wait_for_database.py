import time

from django.core.management.base import BaseCommand, CommandError
from django.db import connections


class Command(BaseCommand):
    help = "Wait until the default database accepts connections."

    def add_arguments(self, parser):
        parser.add_argument("--timeout", type=int, default=60)
        parser.add_argument("--interval", type=float, default=2.0)

    def handle(self, *args, **options):
        timeout = max(options["timeout"], 1)
        interval = max(options["interval"], 0.1)
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            try:
                connections["default"].ensure_connection()
                self.stdout.write(self.style.SUCCESS("Database is ready."))
                return
            except Exception:
                connections["default"].close()
                time.sleep(interval)

        raise CommandError(f"Database was not ready within {timeout} seconds.")
