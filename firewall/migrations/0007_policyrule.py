from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("firewall", "0006_responselog"),
    ]

    operations = [
        migrations.CreateModel(
            name="PolicyRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=120, unique=True)),
                ("description", models.TextField(blank=True)),
                ("enabled", models.BooleanField(default=True)),
                ("priority", models.PositiveIntegerField(default=100)),
                ("action", models.CharField(choices=[("ALLOW", "Allow"), ("TOKENIZE", "Tokenize"), ("BLOCK", "Block")], default="BLOCK", max_length=10)),
                ("direction", models.CharField(choices=[("PROMPT", "Prompt"), ("RESPONSE", "Response"), ("BOTH", "Prompt and response")], default="BOTH", max_length=10)),
                ("roles", models.JSONField(blank=True, default=list)),
                ("excluded_roles", models.JSONField(blank=True, default=list)),
                ("detection_types", models.JSONField(blank=True, default=list)),
                ("keywords", models.JSONField(blank=True, default=list)),
                ("source_contains", models.CharField(blank=True, max_length=120)),
                ("min_risk_score", models.PositiveIntegerField(default=0)),
                ("reason", models.CharField(blank=True, max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ["priority", "name"],
            },
        ),
    ]
