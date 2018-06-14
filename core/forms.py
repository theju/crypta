import datetime

import pgpy

from django import forms
from django.utils.translation import gettext_lazy as gl

from .models import User


class RegisterForm(forms.ModelForm):
    name  = forms.CharField(required=False)
    email = forms.CharField(required=False)

    class Meta:
        model = User
        exclude = ()

    def clean(self):
        data = super(RegisterForm, self).clean()
        pub_key = data.get("public_key")
        public_key, _ = pgpy.PGPKey.from_blob(pub_key)
        recvd_fingerprint = data.get("fingerprint")
        fingerprint = str(public_key.fingerprint).replace(" ", "").lower()
        if fingerprint != recvd_fingerprint:
            raise forms.ValidationError(gl("Invalid fingerprint"), code="invalid")
        return data


class AuthForm(forms.Form):
    public_key = forms.CharField()
    message    = forms.CharField()
    signature  = forms.CharField()

    def clean(self):
        data = super(AuthForm, self).clean()
        signature_blob  = data.get("signature")
        public_key_blob = data.get("public_key")
        msg = data.get("message")

        signature = pgpy.PGPSignature.from_blob(signature_blob)
        public_key, _ = pgpy.PGPKey.from_blob(public_key_blob)

        if not public_key.verify(msg, signature):
            raise forms.ValidationError(gl("Invalid signature"))

        timestamp, _ = msg.split(":", 1)

        utc_now = int(datetime.datetime.utcnow().strftime('%s'))
        if utc_now - int(timestamp) > 300:
            # Don't allow signatures older than 5 minutes
            # To reduce window for replay attack
            raise forms.ValidationError(gl("Signature expired"))

        return data
