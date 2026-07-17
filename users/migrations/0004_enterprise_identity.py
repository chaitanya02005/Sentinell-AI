from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0003_extensiontoken"),
    ]

    operations = [
        migrations.AddField(
            model_name="customuser",
            name="auth_provider",
            field=models.CharField(default="local", max_length=40),
        ),
        migrations.AddField(
            model_name="customuser",
            name="external_subject",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.AddField(
            model_name="customuser",
            name="tenant_id",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="customuser",
            name="department",
            field=models.CharField(blank=True, default="", max_length=120),
        ),
        migrations.AddField(
            model_name="customuser",
            name="identity_claims",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="customuser",
            name="last_sso_login",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddIndex(
            model_name="customuser",
            index=models.Index(fields=["auth_provider", "external_subject"], name="users_sso_subject_idx"),
        ),
    ]
