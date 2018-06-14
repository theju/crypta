# Crypta

Crypta is a web-based password storage vault inspired by [Pass](https://www.passwordstore.org/).

## Overview

Every user either generates OpenPGP keys or loads their existing private key.
All the passwords are encrypted and stored on the server and so the server has
no knowledge of the contents stored on it.

**Note**: Losing the key or passphrase will result in the passwords becoming
inaccessible.

Every password is mapped to a key (could be a url or any other queryable parameter)
and the contents of the password.

```
Encrypted_Key = SHA-256(OpenPGP_Key_Fingerprint + Passphrase + Key)
Encrypted_Val = OpenPGPEncrypt(Val)
```

The above encrypted key is then signed against a time-stamp to prevent a replay
attack.

All the encryption and decryption is performed on the client-side.

## Install

The project can be easily setup using [Pipenv](https://docs.pipenv.org/#install-pipenv-today).

```
$ git clone https://github.com/theju/crypta
$ cd crypta
$ pipenv install
$ pipenv shell
# Create a crypta/local.py file and add the
# `SECRET_KEY`, `DEBUG` and `ALLOWED_HOSTS` django settings attributes
$ python manage.py migratedb
$ python manage.py runserver
```

## Acknowledgements

* [OpenPGP.js](https://openpgpjs.org/) - Handles the client-side encryption and decryption.
* [Django](https://djangoproject.com/) - The application server that powers the REST API.

## License

MIT License.
