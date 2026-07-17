from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("firewall", "0004_risk_score_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="promptlog",
            name="agent_trace",
            field=models.JSONField(default=dict),
        ),
    ]
