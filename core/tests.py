import json
import base64
import hashlib
import datetime

import pgpy

from django.test import TestCase

from .models import User, EncryptedRow


PUBLIC_KEY = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v2.6.2
Comment: https://openpgpjs.org

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
=oPwQ
-----END PGP PUBLIC KEY BLOCK-----
"""

# Used for creating signatures
PRIVATE_KEY = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v2.6.2
Comment: https://openpgpjs.org

xcaGBFp665ABEACPFB17TCOqGIl7xhE4fT3yBjmP+IZe5IdS7pPPAYM21lqo
avpv51kwkyGBRH+UfrraPqWwDCSaurK7BmAyL80L6hCLhWssfW5CPCz0eEeY
bs2fuXC6HMCsTiZjhp4yiLgzfKa4EpJKdZjF/ZiQ30Ho/BgSK+WjrMSJx6kW
fC8+SMRHkoH8OefQYA+TJmOmqH8FxtuonQ8W/ruqt2J0bL+b+208X3BvRF8/
9L9P7qBr7L6PzzydTcSLHrSWzYGTzKSWAhyzXk1oQ4Sm8myHkvudlnJIDjSt
uAOlw2JQf3jtjOnpArSpDecpOiH2xkoJhDqWiyP4/XKjHKSGcCsVvxXMpgNm
PDtT1OIVeFkU7aPEXfQPzRBt+gn/pUQXTxwLtXVVYDbvY68n6S1xIvUOuZCN
8gyo/PcCn7om8zqnsbhzrEi43oodeC/1X9IMpEdHVTpLIhcRsjRnCQNiqRHu
KWGebXlowlbXKqMMYagVV5OMI2ncmNW0zs+1S9QMfGywvg3Urod7YE3T3lEg
O4esV1HthI3xIpRPNZVS6BVKATsRwoy/C4Q0V8S+9hYltRwxcdFz8AeXwX2n
QB53/vtNK44IUxgqCPQ6VfvdYE1rG9tz1R7FIbZoyyqjk6okZdcwYEqxjk1d
KWtBFi4+jJIWicRgqPt9N1BrFMYKcLPMqIcFSwARAQAB/gkDCNuxHOhnP8Ln
YCJ/ypgWbo+46pxMGGldPuwi4qJiIlx4nIfqt9I0nBX3KCNSstbEGZT2cM48
KVuSUMmGbVQB38AnlZRGlwMLHhlaxlbP2RALaT+OTIeSLhOjDwO83OMXMveS
dLdoGwtT1Ok+W8oGcV+nUODLKu0m0nKxQIjJIV9kysE7c3m+w2LuF4UJiftO
qB00O9dgc+7f2sTVlduDwenF90pBn8PPZKbj2htiRGlKLwD13fVsNTKR9Nyr
cPjkQUlIJegDjzZzJyIMOyViYgcS7Ci3dx+wMlzbOcEFLCP0VyOMxZWleUjs
PoMVYqMYL7hZC4iJ1RTWuKUD7+D1YAIZXzqBy6ndLThVR5BVVsdlNUJdy5DO
eoml8xNS8uWOTLLE642z2ygI/tkTu2CbInet5aanepIYBC0azGPGmRggWwsT
0yc910tu6oYxTtSsjAVXyESalunfzv3Z1KIR1Zktzz6YNHGPP4ZL7+7cOpZZ
Fdyuzr6SBWiEOkrFP4M6XUSsVa/jO/haoaddtV4fNSyLRzf8CO+RH6u1jo+M
26E3I8G8kMlne1CxLKC5u7kyIp0zzx0ejKZqMTk8yibnmXGRiAxtiL7u+RBq
NnxRQSZis8nkM09Vzw4mLfniOdd6PzQOQ2y9Rr1EVhxHpzWZWAD/BvJgj0Vb
HqyC7TqYlXUDpJ9Ewv5q2SaClnzFkZdSYdOufGD0Jtto8GnQpvgKpxkcjjHu
Mbj3K3ehGoq52IrJwxSS2UmNinGlqXOENqvZGbqpFpF999Sq9J+D9nbi6qOT
Qe0Z32PzpREvy6tiSTY/LlFENxj+tv8/9m6fWEif3U5OeRHoc0PB/xD6hNpr
vByBJlCEOdLDjlyKbC8ZoHJXN/raaEtzQacUdkrOYE6PVd4MeRzjqP9Geb7C
bFXJpzPXD5HhI0b4LR6Gt6wESU5Byju2LikCC+j7mierY70n05hB5wJRaOWO
z6kWgKl223RS8PurKTwmDqLJGagTNehyL5knGFPROBGnPpxAamxStdXIWf/K
QDeXoXqGlCY9J72O1vraLt3qvoD+zrkH8B9I2isAikXwa9EZqyoL5tyMDLI4
SInfKxYwpU0POyroDxwoWuookRjEipgO7RLYPyI91h0/+P6F3E8i3+jCgbS1
guEBirya+Euhv0gBPQFwtbriYpoEtEgtcf7YBdEVuERafE0Q0vPcvF8EDcRK
TKUyDTiq6EdtDwDYjILOG7ar+WMR3W8ehBtsyBX/N5Ajwd5szy81lNV2RQQ6
akna6LraaWjwIqPxqDSMdGeSMSKJVtXByvovNHJcBeM12GshhNc5IIg0qJer
VEFzuOaOtfeLffNvywwe3OT/YySoSyv0dHtF8HokZd5jDpDeCyXKIhrhEa/K
9livXaJX6UYNYuq8XcwkVjo5pCAfVbiS/TwTzxEAiCgVP/XNk7jza3CdhxsI
Rq3nP2yziTkcWTude/lPHfH7As1pRpU0cO9IwPFameEIgoaYFG/DothsM6sm
nnxTMeyetwVhBDeARSHj3atZrDeNwq/KJ8WDmsvaHJL5ZQM+HXiFrtKrfvB3
X/NsW/XDMdhtUZf/s7sE7qKjO00V3P9ew6X/Np8Ud4ov1CjWmYgRL2rVeKLs
sNlYdgQyq6u9sdEvrWt5prIaD57sKZREkLTsBeW4RDtdsB8Ix63x/U6fvOac
AVCcfvzmg2GmhD3Y6Xv2NDEE1kjP1GM/SDzFbnOFDZuZDmxUabDn8EFEaDL2
UHJPpGdvayDNrbedAEBfyF0x0snNGVRoZWp1IDx0aGVqdUBleGFtcGxlLmNv
bT7CwXUEEAEIACkFAlp665EGCwkHCAMCCRCiiC3LzPBDcwQVCAoCAxYCAQIZ
AQIbAwIeAQAAjtkQAILvVQ+faryGal3Y4REGjrmc+7+VxqzDaVCoRoHHGa7H
R5NM5TW2ZU1EbtXnLVAz0ANmxRIXe5/dSbzJgZOCBISBKtgb5Nt3HmRBPZ79
i75nvCWcG/nkepb+fX4QmYnuIZfMS1KhUxIh5rPLBS/XUZ412B4G2SvgciJy
hg82QcMBnzqidtxOoc/7Gn50MuPZu5wmy0v8zmMUYcPgMtJAiHvqQP+fWEKu
u0ywHJz4/qhhPJ/zNSc60JwY+CcomuTRQ7/KNEfLbWeY/ED+0BnkdZXtRMDC
fpeT56hAwRiJ4X5HPyoD6KkI/uJEvXOMsvNj6s2/a4KayZf9DZ3HDdHCpqpN
C9QRsiSJInvcEhIqkMMg1lZAkyOfUix9k853EmnppmXPFeB/ImA1Z2Xpqi/a
oRS4a3sAElrLcDZPsh22y82PShgP0zHFjDP+KoRwOLThF/uRXol/+szm5qbC
YW0SHiMG+jeUAKDGGHGR8xrm0a9kDLavKrEjwddO/u/df87PdmsThrFuZF1c
sCGfuUZ0SmYnKY7MDP4Oge35nxvEvxvXge1VnChJDs2JqxXh+ZIo9AC4m13s
jDdUyL19B09syay44rr6mPHhrTyFRcBNLIrinQXXymkO+AK8Y62ihUIw396p
sQBpCYh7MkHV7rs2KotdoT0SAaToKO+RH9IgvbhRx8aGBFp665ABEACv+Y/C
paZFgrs1mSCPnfgYDUG7RC6oGFrvyRSz2AVU7VmMd2pCP6ZwPi1+yrHcnbX1
6HyYVeBrUJcy8F1CwCt/kZcg9yJRpkZzU7r8jWQAC6T50UKcA7ul1DyFDcD6
4D7DZReXoN341ppxXl8MO2xK76hNq4InrJz8I6JHLK+GVIf10BZbiT2+OfYk
7k2UxNvcrQyBabAoAMTkPMgdk9LSXROOTAnrZV2aBQ5COcmsFJGRovO33OVs
nrGZdl/XFPRpo55K/0RUEuUGbOOHwLXsgoHjnXGf1yf/cOEQhQiKR8/vLkFZ
cDznTsAzfrVk81bcV0krmcWk70+ZesrUj0g8i1/9nR24TUHdpusmnMq4vaJw
Xv03elLfy9B0DF0nc+1h/MyGqFhMeXuW2veuXDgWAm19JKzGsr85khE/scsF
qKhYSlN2ZnsLZCQzWuJqdzXYHGXj4l7QC5GRWs6RUviigElEgHToumQ8iWJS
oYD0EGikVGNDnUjPwL0AvrYRUhxRd9ieTYbFm82fiDXRxfZx0Y405bkLIumH
wHeLFcywXNztFzO99DF2iOOuvvSRVpT6u8tDKxZGzrgwsPQskM/53WdGyk3c
TW5zDhaSe2jCI+E0k16TcSOBnY3YFgdczrWR86dHSKbCatCH1/Uh4ipapmZF
TEROYGzrwvVX4E61dwARAQAB/gkDCIoRuk7Bj2IdYGoZre4+tAsFwVvpRseT
3x4vo5eqLglgkubdFe37UxDi1Z/r0Clq5nvjxVsVkCRlbjNkLGpmuNdG+hNi
3LIm2tnBDJ+VZWyIcBZU0/IA1p+TyleOAQkwvCRyB74yagAZx9B5XifxicJs
k9Ocev8IPjNmyfQfZsfJ2UYVbrMbcWcd4O2V4xjL6a+/PsrqOfwOSc2erHuW
lRPyr6p/arJ0LGFm7KDHdIxFiyd9c9Y2XXy2D8U7+GyzFdKVv4HlF3XXCSzQ
g4Rtg9+B2Wa2HqHXBMEJ4CsPyJOLzsOaqA3gm5WgtDB3qQIH644XKoRzN1a8
+18FRqFWrKL+2xsPdc6z9rI4yCcAkz1T8GKto5fNtqmmss5RDo/uOPLY9z6f
gh7nPpEFviWhw1jotCI5l1it93wOrSpcZcGmnPn1c1s9Z2QaP0hpjzX0/slF
B6YarfCsTJ8YXu2ToS8TjKtiD8I+V9BUyqgzOx7v3l4Aaj2TDFu0lMiI8ICZ
DLc5/oKWqwV60KgD84gmn5qoo+BKXskNESqPJEkYniyYKGHzN4+0UH3XIO7C
m+jspvpusaLKlD24zE3fLLuH42/CnL+ZQodLMDJk+yzZQlyFjTA+lBlYa7aK
9/RBU2uwX5jyuncqRoTb0of6PP9NrY2wDt7WfR1H6s8HRqKhp0UGqb498aQz
rNO6IMf4hQo4Tt0CFJ5VBEaXpaZapQcxRDU1vz7FbUIhCCaytTWubkjS7bFP
Kd8HBnCVYm2rnAUmPZr4QkyX220o578yYGMUpP+pzjCXtOBR2u4dobLnAqi+
zy3y2vBDQQ9uZh9S/0EJBDlFHIJthQ3WE0eFTSfew3askgZn0PD3EozM1Bck
B7+NiX2H8a1Rlt0tTVQv4MPV3eyGgATNjRm5uSa4Lx5viFJXnhOozjc3tV88
MAWaXAm2wwcQXU6eMJs7T5Zhhc0959+psK4nFFoC1G3d9w+5aJp4cR7B+rfi
WPbenaRTbZBHnEFGDbMzcxQ/Ll7nr1VrhT9KjM7LNHfYqK48V3E3pDBymjR7
6wdoxrGhJw+ykVYONv76hGTy8fiGiOT868ZIMA1v0w7oTe/nCjf84TO0Fh+Q
G6FjhoBRWehKR/f+E6fWIB2fB0mZmOpfwHKaQteLUqcqgM/rg/7ZFd4gIklQ
xsZdl3R8ieb6uqOsTLEJDISLI8/M9tebauSTialAW8v5V314cgDIjnyunfH5
3+Om3Vo3HhJRBk42tZ941DziCudY9ubPSP0wDz+diM6dbE/m9f6d5WA/oZH5
tunbqc+NEciNSN0zc9Ujon0bNOZOLrVq3WYoWqLeARVmMwOTELj0zNwJDlNS
WqFI79mxnNCCnselKbsjdR4JTziLv4f3f6BKCK29pBEcVhvyZutksO6yqxQ/
H57aKY/DTG9GcXA78duDYmAp72Lf2flxiyjpmkFxjxhWngED4n04/H86tIp7
FmMmfqpGdQJ+l5RdRsLgjTDvg6pw/SLs4g81UdM/sH9BjrFDTLR8VK+FG/PH
VYMyBgV6oX0AT91SomlgycfWTEO4idTU7vjvjE8pLt1KjXS4Ud5IiwAo79Z0
te6QXL9c2EgzG+VvCmSd7um/5D2cvP9xAXUKS0CwM6PBVZapl8GVrijAIj/H
lsPAQ8LCoSh524F9l0TsMzi40kc0e+gLSES7OTABctamjl9Fr9Fiv4TfsWaA
IeMI9K9HN9HlHaQhgas5BdCRmCl6YnXPzcCVGXeS9S1qTjuMZS9PAXcFoL+R
LPBARmLCwV8EGAEIABMFAlp665IJEKKILcvM8ENzAhsMAAAM7g//Z+mSCBSn
9OY1Xp/dbiYHk5IaoMp2jlrHUAn6MHTUaOxI0FK74VaLG+bICgdV/fi6NKiH
uB64o9IOMEv/toZpxMoaor1p8LFZD4Fii9PPOUIb+o1pf8gSZpnl1oO6G3YM
J29HPjfG14evabMbMEBKPl7oBDD35IYxXnoig80Ngan1/1PYUpAKHOZ+wZmr
rJ5uitu84kxv5ZaffPpE3nl2StPJLpxy1mjw59oVfF0iMzebfbD8bm+MrjyA
UeViwWiOBiLH5jDPVOS/Sf9FKl4WDTCjz27RA47AaJZh84ecTyH3rIyk4qFC
oWM0So3C/EAtUrZuOCMtTTXKcEJWL3i9pR6HBXFKMwVCxigj8cplQ+fv3Vb2
aqk/qkrqysHOkPVMNtR0q334QOGCoq5DsCjurhiqbvAXEJWaKN1Rem9M7UAU
SJZqpTl8bqHDqXI57cAgmeuoga2oAFA9YafPv/3CqB5M8Cs6iYS6Iq48r4gZ
OGwAcgRs1mT3AizfU+7j7JED8ffI349ljHihqknv47+zngP69z41Hepyesw/
htRgbVr7aLiezClfoZHuyanKnNr/5mfzXfBPH5wR6DCvZQXz5B+T9P/VLLxY
/0gTIKjx42GsPGUKsylWrq2osLCt0m8AWWTVBaIVX/cA3bedxtbZhABbAfBJ
ClCvQwPfvmA2FwI=
=kWMa
-----END PGP PRIVATE KEY BLOCK-----
"""

PASSPHRASE = "abcd"


class CoreTestCase(TestCase):
    def _register(self):
        obj = self._signature()
        fingerprint = obj["fingerprint"]
        User.objects.create(
            name="Theju",
            email="theju@example.com",
            fingerprint=fingerprint,
            public_key=PUBLIC_KEY
        )

    def _signature(self, key=''):
        public_key, _ = pgpy.PGPKey.from_blob(PUBLIC_KEY)
        fingerprint = str(public_key.fingerprint).replace(" ", "").lower()
        private_key, _ = pgpy.PGPKey.from_blob(PRIVATE_KEY)

        message = datetime.datetime.utcnow().strftime("%s") + ':' + key
        signature = ""
        with private_key.unlock(PASSPHRASE) as sec_key:
            msg = pgpy.PGPMessage.new(message, cleartext=True)
            signature = str(sec_key.sign(msg))

            auth_str = str(fingerprint) + ":"
            fingerprint_b64 = base64.urlsafe_b64encode(auth_str.encode())
            auth_header = "Basic {0}".format(fingerprint_b64.decode())

            return {
                "fingerprint": fingerprint,
                "message": message,
                "signature": signature,
                "auth_header": auth_header
            }

    def _create_encrypted_kv(self):
        user = User.objects.all()[0]
        val_msg = pgpy.PGPMessage.new("secret_password")

        pub_key, _ = pgpy.PGPKey.from_blob(PUBLIC_KEY)
        enc_key = hashlib.sha256(
            "{0}{1}google.com".format(
                user.fingerprint,
                PASSPHRASE
            ).encode(),
        ).hexdigest()
        enc_val = str(pub_key.encrypt(val_msg))
        EncryptedRow.objects.create(
            user=user,
            key=enc_key,
            val=enc_val
        )

    def _encrypt(self, key, val):
        user = User.objects.all()[0]
        pub_key, _ = pgpy.PGPKey.from_blob(PUBLIC_KEY)
        val_msg = pgpy.PGPMessage.new(val)
        enc_key = hashlib.sha256(
            "{0}{1}{2}".format(user.fingerprint, PASSPHRASE, key).encode()
        ).hexdigest()
        enc_val = str(pub_key.encrypt(val_msg))
        return (enc_key, enc_val)

    def _decrypt(self, message):
        priv_key, _ = pgpy.PGPKey.from_blob(PRIVATE_KEY)
        msg = pgpy.PGPMessage.from_blob(message)
        with priv_key.unlock(PASSPHRASE) as sec_key:
            return sec_key.decrypt(msg).message

    def test_register(self):
        obj = self._signature()
        fingerprint = obj["fingerprint"]
        response = self.client.post("/register/", {
            "name": "Theju",
            "email": "theju@example.com",
            "fingerprint": fingerprint + "a",
            "public_key": PUBLIC_KEY
        })
        self.assertEqual(response.status_code, 400)

        response = self.client.post("/register/", {
            "public_key": PUBLIC_KEY
        })
        self.assertEqual(response.status_code, 400)

        response = self.client.post("/register/", {
            "fingerprint": fingerprint,
            "public_key": PUBLIC_KEY
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.all().count(), 1)

        User.objects.all().delete()

        response = self.client.post("/register/", {
            "name": "Theju",
            "email": "theju@example.com",
            "fingerprint": fingerprint,
            "public_key": PUBLIC_KEY
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.all().count(), 1)

    def test_unregister(self):
        obj = self._signature()
        fingerprint = obj["fingerprint"]
        signature = obj["signature"]
        message = obj["message"]
        auth_header = obj["auth_header"]
        self._register()
        response = self.client.post(
            "/unregister/", {
                "message": message,
                "signature": signature
            },
            HTTP_AUTHORIZATION=auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.all().count(), 0)

    def test_invalid_signature(self):
        obj = self._signature()
        self._register()
        user = User.objects.all()[0]
        key = "abcdef"
        EncryptedRow.objects.create(
            user=user,
            key=key,
            val=key
        )
        msg = int(datetime.datetime.utcnow().strftime("%s")) - 1000
        response = self.client.post(
            "/get/", {
                "key": key,
                "message": msg,
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/get/", {
                "key": key,
                "message": msg,
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION="Basic {0}".format(base64.b64encode(b"abcd:").decode()))
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/get/", {
                "key": key,
                "message": obj["message"],
                "signature": obj["signature"].replace("a", "b")
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/get/", {
                "key": key,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 200)

    def test_get(self):
        self._register()
        self._create_encrypted_kv()
        row = EncryptedRow.objects.all()[0]
        obj = self._signature(row.key)
        response = self.client.post(
            "/get/", {
                "key": row.key + "a",
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 404)

        response = self.client.post(
            "/get/", {
                "key": row.key,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 200)
        msg = json.loads(response.content)
        self.assertEqual(self._decrypt(msg["val"]), "secret_password")

    def test_get_no_auth(self):
        self._register()
        obj = self._signature()
        key = ""
        response = self.client.post(
            "/get/", {
                "key": key,
                "message": obj["message"],
                "signature": obj["signature"]
            })
        self.assertEqual(response.status_code, 400)

    def test_post(self):
        self._register()
        key, val = self._encrypt("facebook.com", "fb_secret_password")
        obj = self._signature(key)
        response = self.client.post(
            "/post/", {
                "key": key,
                "val": val,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRow.objects.all().count(), 1)
        msg = json.loads(response.content)
        self.assertEqual(self._decrypt(msg["val"]), "fb_secret_password")

        key, val = self._encrypt("facebook.com", "fb_new_password")
        response = self.client.post(
            "/post/", {
                "key": key,
                "val": val,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(EncryptedRow.objects.all().count(), 1)

    def test_update(self):
        self._register()
        key, val = self._encrypt("facebook.com", "fb_password")
        obj = self._signature(key)
        response = self.client.post(
            "/post/", {
                "key": key,
                "val": val,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.content)
        self.assertEqual(self._decrypt(response["val"]), "fb_password")

        key, val = self._encrypt("facebook.com", "fb_new_password")
        response = self.client.post(
            "/update/", {
                "key": key + "a",
                "val": val,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 404)

        key, val = self._encrypt("facebook.com", "fb_new_password")
        response = self.client.post(
            "/update/", {
                "key": key,
                "val": val,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.content)
        self.assertEqual(self._decrypt(response["val"]), "fb_new_password")

    def test_delete(self):
        self._register()
        key, val = self._encrypt("google.com", "fb_password")
        obj = self._signature(key)
        response = self.client.post(
            "/post/", {
                "key": key,
                "val": val,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRow.objects.all().count(), 1)

        response = self.client.post(
            "/delete/", {
                "key": key + "a",
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"]
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(EncryptedRow.objects.all().count(), 1)

        response = self.client.post(
            "/delete/", {
                "key": key,
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"]
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(EncryptedRow.objects.all().count(), 0)

    def test_export(self):
        self._register()
        user = User.objects.all()[0]
        obj = self._signature()
        for ii in range(2):
            EncryptedRow.objects.create(
                user=user,
                key="key_" + str(ii),
                val="val_" + str(ii)
            )
        response = self.client.post(
            "/export/", {
                "message": obj["message"],
                "signature": obj["signature"]
            },
            HTTP_AUTHORIZATION=obj["auth_header"])
        self.assertEqual(response.status_code, 200)
        rows = json.loads(response.content)["rows"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["key"], "key_0")
        self.assertEqual(rows[0]["val"], "val_0")
        self.assertEqual(rows[1]["key"], "key_1")
        self.assertEqual(rows[1]["val"], "val_1")
