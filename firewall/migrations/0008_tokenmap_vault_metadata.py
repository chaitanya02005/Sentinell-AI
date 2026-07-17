from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("firewall", "0007_policyrule"),
    ]

    operations = [
        migrations.AddField(
            model_name="tokenmap",
            name="vault_provider",
            field=models.CharField(default="legacy-fernet", max_length=80),
        ),
        migrations.AddField(
            model_name="tokenmap",
            name="vault_key_id",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="tokenmap",
            name="vault_purpose",
            field=models.CharField(default="pii_token_map", max_length=80),
        ),
        migrations.AddField(
            model_name="tokenmap",
            name="vault_version",
            field=models.PositiveIntegerField(default=0),
        ),
    ]
