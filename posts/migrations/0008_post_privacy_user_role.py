# Generated by Django 5.1.5 on 2025-03-17 11:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('posts', '0007_follow'),
    ]

    operations = [
        migrations.AddField(
            model_name='post',
            name='privacy',
            field=models.CharField(choices=[('public', 'Public'), ('private', 'Private')], default='public', max_length=10),
        ),
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('admin', 'Admin'), ('user', 'User'), ('guest', 'Guest')], default='user', max_length=10),
        ),
    ]
