"""
Management command to create demo test users for Sentinell.AI.

Usage:
    python manage.py create_test_users
"""

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()

TEST_USERS = [
    {
        "username": "admin",
        "email": "admin@sentinell.ai",
        "password": "Admin123!",
        "role": "ADMIN",
        "is_staff": True,
        "is_superuser": True,
        "first_name": "Alice",
        "last_name": "Admin",
    },
    {
        "username": "employee",
        "email": "employee@sentinell.ai",
        "password": "Emp123!",
        "role": "EMPLOYEE",
        "first_name": "Bob",
        "last_name": "Employee",
    },
    {
        "username": "intern",
        "email": "intern@sentinell.ai",
        "password": "Int123!",
        "role": "INTERN",
        "first_name": "Charlie",
        "last_name": "Intern",
    },
]


class Command(BaseCommand):
    help = "Creates demo test users (admin, employee, intern) for Sentinell.AI"

    def handle(self, *args, **options):
        for data in TEST_USERS:
            username = data["username"]
            if User.objects.filter(username=username).exists():
                self.stdout.write(self.style.WARNING(f"  User '{username}' already exists – skipping."))
                continue

            user = User.objects.create_user(
                username=data["username"],
                email=data["email"],
                password=data["password"],
                role=data["role"],
                first_name=data.get("first_name", ""),
                last_name=data.get("last_name", ""),
                is_staff=data.get("is_staff", False),
                is_superuser=data.get("is_superuser", False),
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"  ✓ Created {user.get_role_display()} user: {username} / {data['password']}"
                )
            )

        self.stdout.write(self.style.SUCCESS("\nDemo users ready! Visit http://127.0.0.1:8000/login/"))
