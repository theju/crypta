from django.db import models


class User(models.Model):
    name  = models.CharField(max_length=50, null=True)
    email = models.EmailField(null=True)
    fingerprint = models.CharField(max_length=40, unique=True)
    public_key  = models.TextField()

    def __str__(self):
        return self.name


class EncryptedRow(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    key  = models.TextField()
    val  = models.TextField()

    class Meta:
        unique_together = ("user", "key")
