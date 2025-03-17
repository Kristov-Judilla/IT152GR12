# Generated by Django 5.1.6 on 2025-02-27 12:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('posts', '0004_alter_user_options_alter_user_managers_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='post',
            name='metadata',
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name='post',
            name='title',
            field=models.CharField(default='password123', max_length=255),
            preserve_default=False,
        ),
    ]
