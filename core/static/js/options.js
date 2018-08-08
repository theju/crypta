(function() {
    var $ = function(sel) {
        return document.querySelector(sel);
    };
    var opts = JSON.parse(sessionStorage.getItem('gpg_options') || '{}');
    if (Object.keys(opts).length > 0) {
        $('[name=public_key]').value = opts.public_key;
        $('[name=private_key]').value = opts.private_key;
        $('[name=passphrase]').value = opts.passphrase;
        $('[name=server]').value = opts.server;
        $('.download').classList.remove('hidden');
    } else {
        $('.settings').classList.add('settings', 'hidden');
        $('.generate').classList.remove('hidden');
    }
    $('input[name=url]').value = window.location.href.replace('/options/', '').replace('#', '');

    $('.generate form').addEventListener('submit', function(ev) {
        ev.preventDefault();
        $('.generate form input[type=submit]').value = 'Generating...';
        $('.generate form input[type=submit]').setAttribute('disabled', 'disabled');
        var name = $('.generate [name=name]').value;
        var email = $('.generate [name=email]').value;
        var userIds = [{
            name: name,
            email: email
        }];
        var passphrase = $('.generate [name=passphrase]').value;
        var options = {
            userIds: userIds,
            numBits: 2048,
            passphrase: passphrase
        };

        openpgp.generateKey(options).then(function(obj) {
            var privkey = obj.privateKeyArmored;
            var pubkey = obj.publicKeyArmored;
            var fingerprint = obj.key.primaryKey.fingerprint;
            var server = $('.generate [name=server]').value;
            var opts = {
                public_key: pubkey,
                private_key: privkey,
                passphrase: passphrase,
                server: server,
                fingerprint: fingerprint
            };
            if (name) {
                opts.name = name;
            }
            if (email) {
                opts.email = email;
            }
            sessionStorage.setItem('gpg_options', JSON.stringify(opts));
            uploadToServer(opts);
        });
    });

    function uploadToServer(opts) {
        $('.settings').classList.remove('hidden');
        $('.generate').classList.add('generate', 'hidden');
        $('[name=public_key]').value = opts.public_key;
        $('[name=private_key]').value = opts.private_key;
        $('[name=passphrase]').value = opts.passphrase;
        $('[name=server]').value = opts.server;

        var fd = new FormData();
        if (opts.name) {
            fd.append('name', opts.name);
        }
        if (opts.email) {
            fd.append('email', opts.email);
        }
        fd.append('fingerprint', opts.fingerprint);
        fd.append('public_key', opts.public_key);
        fetch(opts.server + '/register/', {
            method: 'POST',
            body: fd
        }).then(function() {
            $('.download').classList.remove('hidden');
        });
    }

    $('.generate .import a').addEventListener('click', function() {
        $('.generate').classList.add('generate', 'hidden');
        $('.settings').classList.remove('hidden');
        $('.settings .import').classList.remove('hidden');
    });

    $('.settings form').addEventListener('submit', function(ev) {
        ev.preventDefault();
        var pubkey = $('.settings [name=public_key]').value;
        var pubkeyObj = openpgp.key.readArmored(pubkey).keys[0];
        var privkey = $('.settings [name=private_key]').value;
        var passphrase = $('.settings [name=passphrase]').value;
        var server = $('.settings [name=server]').value;
        var fingerprint = pubkeyObj.primaryKey.fingerprint;
        sessionStorage.setItem('gpg_options', JSON.stringify({
            public_key: pubkey,
            private_key: privkey,
            passphrase: passphrase,
            server: server,
            fingerprint: fingerprint
        }));
        var fd = new FormData();
        fd.append('fingerprint', fingerprint);
        fd.append('public_key', pubkey);
        fetch(server + '/register/', {
            method: 'POST',
            body: fd
        }).then(function() {
            $('.settings .import').classList.add('import', 'hidden');
            $('.download').classList.remove('hidden');
        });
    });

    $('.download a').addEventListener('click', function() {
        var privkey = $('.settings [name=private_key]').value;
        var aa = document.createElement('a');
        aa.download = 'secret.key';
        aa.href = `data:text/plain;charset=utf-8,${privkey}`;
        document.body.appendChild(aa);
        aa.click();
        document.body.removeChild(aa);
    });

    $('[name=keys_file]').addEventListener('change', function (ev) {
        var fr = new FileReader();
        fr.addEventListener('load', function (event) {
            var data = event.target.result;
            var keys = openpgp.key.readArmored(data).keys;
            if (keys.length > 0) {
                var privKeyObj = keys[0];
                $('[name=private_key]').value = data;
                var pubKeyData = privKeyObj.primaryKey.writePublicKey();
                $('[name=public_key]').value = privKeyObj.toPublic().armor();
            }
        });
        fr.readAsText(ev.target.files[0]);
    });
})();
