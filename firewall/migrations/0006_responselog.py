from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("firewall", "0005_promptlog_agent_trace"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ResponseLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source", models.CharField(default="browser_extension", max_length=80)),
                ("original_response", models.TextField()),
                ("processed_response", models.TextField(blank=True)),
                ("detected_types", models.JSONField(default=list)),
                ("action", models.CharField(choices=[("ALLOW", "Allow"), ("REDACT", "Redact"), ("BLOCK", "Block")], max_length=10)),
                ("reasons", models.JSONField(default=list)),
                ("risk_score", models.IntegerField(default=0)),
                ("risk_level", models.CharField(default="LOW", max_length=10)),
                ("agent_trace", models.JSONField(default=dict)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ["-timestamp"],
            },
        ),
    ]
