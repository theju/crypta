# Generated by Django 2.2.4 on 2019-08-03 07:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='fingerprint',
            field=models.TextField(unique=True),
        ),
    ]
