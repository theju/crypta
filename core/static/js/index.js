(function() {
    let gpgOpts = {};

    let $ = function(sel) { return document.querySelector(sel); };

    fetchOpts();
    $('#search').focus();

    $('#search').addEventListener('keydown', function(ev) {
        if (ev.target.value.trim().length === 0) {
            $('.add textarea').value = '';
            $('.add').classList.add('add', 'hidden');
            $('input[name=mode]').value = 'post';
            $('.add input[name=add]').value = 'Add';
            $('.delete_container').classList.add('delete_container', 'hidden');
        }
        if (ev.key.toLowerCase() === 'enter') {
            $('.error').innerText = '';
            getData($('#search').value).then(function() {}).catch(function() {});
        }
    });

    function getData(val) {
        return new Promise(function(resolve, reject) {
            let fd = new FormData();
            let fingerprint = gpgOpts.fingerprint;
            let passphrase = gpgOpts.passphrase;
            let key = fingerprint + passphrase + val;
            let buffer = new TextEncoder("utf-8").encode(key);
            crypto.subtle.digest("SHA-256", buffer).then(function(bf) {
                let encKey = hex(bf);
                let message = '' + (new Date()).getTime() + ':' + encKey;
                openpgp.sign({
                    data: message,
                    privateKeys: [gpgOpts.privateKeyObj],
                    armor: true,
                    detached: true
                }).then(function(signatureObj) {
                    fd.append('key', encKey);
                    fd.append('message', message);
                    fd.append('signature', signatureObj.signature);
                    let headers = {
                        Authorization: 'Basic ' + btoa(fingerprint + ':')
                    };
                    fetch(gpgOpts.server + '/get/', {
                        method: 'POST',
                        body: fd,
                        headers: headers
                    }).then(function(response) {
                        if (response.status === 404) {
                            $('.contents').classList.remove('hidden');
                            $('.contents').innerText = 'Not Found. Create a new one?';
                            $('.add textarea').value = 'Key: ' + $('#search').value + '\r\n';
                            $('.add').classList.remove('hidden');
                            reject();
                        } else if (response.status === 400) {
                            response.json().then(function(data) {
                                $('.contents').classList.remove('hidden');
                                $('.contents').innerText = data.error;
                                $('.add textarea').value = '';
                                reject(data);
                            });
                        } else {
                            response.json().then(function(data) {
                                decrypt(data.val).then(function(val) {
                                    $('.add').classList.remove('hidden');
                                    $('.add textarea').value = val.data;
                                    $('input[name=mode]').value = 'update';
                                    $('.add input[name=add]').value = 'Update';
                                    $('.delete_container').classList.remove('hidden');
                                    resolve(val);
                                });
                            });
                        }
                    });
                });
            });
        });
    }

    $('.add input[name=add]').addEventListener('click', function(ev) {
        let $this = ev.target;
        $this.setAttribute('disabled', 'disabled');
        let mode = $('input[name=mode]').value;
        let val = $('.add textarea').value;
        postData({key: $('#search').value, mode: mode, val: val}).then(function() {
            $this.removeAttribute('disabled');
        });
    });

    function postData(obj) {
        return new Promise(function(resolve, reject) {
            let fd = new FormData();
            let fingerprint = gpgOpts.fingerprint;
            let passphrase = gpgOpts.passphrase;
            let key = fingerprint + passphrase + obj.key;
            let val = obj.val;
            let buffer = new TextEncoder("utf-8").encode(key);
            crypto.subtle.digest("SHA-256", buffer).then(function(bf) {
                let encKey = hex(bf);
                let message = '' + (new Date()).getTime() + ':' + encKey;
                openpgp.sign({
                    data: message,
                    privateKeys: [gpgOpts.privateKeyObj],
                    armor: true,
                    detached: true
                }).then(function(signatureObj) {
                    openpgp.encrypt({
                        data: val,
                        publicKeys: [gpgOpts.publicKeyObj],
                        privateKeys: gpgOpts.privateKeyObj
                    }).then(function(encVal) {
                        fd.append('key', encKey);
                        fd.append('val', encVal.data);
                        fd.append('message', message);
                        fd.append('signature', signatureObj.signature);
                        let headers = {
                            Authorization: 'Basic ' + btoa(fingerprint + ':')
                        };
                        fetch(gpgOpts.server + '/' + obj.mode + '/', {
                            method: 'POST',
                            body: fd,
                            headers: headers
                        }).then(function(response) {
                            if (response.status === 400) {
                                response.json().then(function(data) {
                                    $('.contents').innerText = 'Error';
                                    setTimeout(function() {
                                        $('.contents').innerText = '';
                                    }, 5000);
                                    reject(data);
                                });
                            } else {
                                response.json().then(function(data) {
                                    $('.contents').classList.remove('hidden');
                                    $('.contents').innerText = obj.mode === 'post' ? 'Added' : 'Updated';
                                    if (obj.mode === 'post') {
                                        $('.add input[name=mode]').value = 'update';
                                        $('.add input[name=add]').value = 'Update';
                                        $('.delete_container').classList.remove('hidden');
                                    }
                                    setTimeout(function() {
                                        $('.contents').innerText = '';
                                    }, 5000);
                                    resolve(data);
                                });
                            }
                        });
                    });
                });
            });
        });
    }

    $('.delete').addEventListener('click', function() {
        deleteData($('#search').value).then(function() {
            $('.contents').innerText = 'Deleted';
            $('.add textarea').value = '';
            $('.add').classList.add('add', 'hidden');
            $('input[name=mode]').value = 'post';
            $('.add input[name=add]').value = 'Add';
            setTimeout(function() {
                $('.contents').innerText = '';
            }, 5000);
            $('.add').classList.add('add', 'hidden');
        }).catch(function() {});
    });

    function deleteData(val) {
        return new Promise(function(resolve, reject) {
            let fd = new FormData();
            let fingerprint = gpgOpts.fingerprint;
            let passphrase = gpgOpts.passphrase;
            let key = fingerprint + passphrase + val;
            let buffer = new TextEncoder("utf-8").encode(key);
            crypto.subtle.digest("SHA-256", buffer).then(function(bf) {
                let encKey = hex(bf);
                let message = '' + (new Date()).getTime() + ':' + encKey;
                openpgp.sign({
                    data: message,
                    privateKeys: [gpgOpts.privateKeyObj],
                    armor: true,
                    detached: true
                }).then(function(signatureObj) {
                    fd.append('key', encKey);
                    fd.append('message', message);
                    fd.append('signature', signatureObj.signature);
                    let headers = {
                        Authorization: 'Basic ' + btoa(fingerprint + ':')
                    };
                    fetch(gpgOpts.server + '/delete/', {
                        method: 'POST',
                        body: fd,
                        headers: headers
                    }).then(function(response) {
                        if (response.status === 400) {
                            response.json().then(function(data) {
                                $('.contents').innerText = 'Error';
                                reject(data);
                            });
                        } else {
                            response.json().then(function(data) {
                                $('.contents').innerText = 'Deleted';
                                resolve(data);
                            });
                        }
                    });
                });
            });
        });
    }

    function fetchOpts() {
        let obj = localStorage.getItem('gpg_options');
        if (!obj) {
            window.location = '/options/';
        } else {
            gpgOpts = JSON.parse(obj);
            gpgOpts.publicKeyObj = openpgp.key.readArmored(gpgOpts.public_key).keys[0];
            gpgOpts.privateKeyObj = openpgp.key.readArmored(gpgOpts.private_key).keys[0];
            gpgOpts.privateKeyObj.decrypt(gpgOpts.passphrase).catch(function(err) {
                $('.error').innerText = err;
            });
        }
    }

    function hex(buffer) {
        /* From https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest */
        let hexCodes = [];
        let view = new DataView(buffer);
        for (let i = 0; i < view.byteLength; i += 4) {
            // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
            let value = view.getUint32(i);
            // toString(16) will give the hex representation of the number without padding
            let stringValue = value.toString(16);
            // We use concatenation and slice for padding
            let padding = '00000000';
            let paddedValue = (padding + stringValue).slice(-padding.length);
            hexCodes.push(paddedValue);
        }

        // Join all the hex strings into one
        return hexCodes.join("");
    }

    function fetchRows(pageNum) {
        return new Promise(function(resolve, reject) {
            let fd = new FormData();
            let fingerprint = gpgOpts.fingerprint;
            let passphrase = gpgOpts.passphrase;
            let key = fingerprint + passphrase;
            let buffer = new TextEncoder("utf-8").encode(key);
            crypto.subtle.digest("SHA-256", buffer).then(function(bf) {
                let encKey = hex(bf);
                let message = '' + (new Date()).getTime() + ':' + encKey;
                openpgp.sign({
                    data: message,
                    privateKeys: [gpgOpts.privateKeyObj],
                    armor: true,
                    detached: true
                }).then(function(signatureObj) {
                    fd.append('message', message);
                    fd.append('signature', signatureObj.signature);
                    fd.append('page', pageNum);

                    let headers = {
                        Authorization: 'Basic ' + btoa(fingerprint + ':')
                    };
                    fetch(gpgOpts.server + '/export/', {
                        method: 'POST',
                        body: fd,
                        headers: headers
                    }).then(function(response) {
                        $('.contents').classList.remove('hidden');
                        if (response.status === 400) {
                            response.json().then(function(data) {
                                $('.contents').innerText = 'Error';
                                setTimeout(function() {
                                    $('.contents').innerText = '';
                                }, 5000);
                                reject(data);
                            });
                        } else {
                            response.json().then(function(data) {
                                $('.add').classList.add('hidden');
                                $('.contents').classList.remove('hidden');
                                $('.contents').innerText = '';
                                let rows = data.rows;
                                if (rows.length === 0) {
                                    $('.contents').innerText = 'No rows found';
                                } else {
                                    let ul = document.createElement('ul');
                                    ul.classList.add('rows');
                                    for (let ii = 0; ii < rows.length; ii++) {
                                        let vv = decrypt(rows[ii].val);
                                        vv.then(function(val) {
                                            let data = val.data;
                                            let lines = data.split("\n");
                                            let key = lines[0];
                                            let li = document.createElement('li');
                                            li.classList.add('row');
                                            li.innerHTML = `${key} <a href="javascript:void(0)">View</a><br>`
                                                + `<span class="hidden">${lines.splice(1).join('\n')}</span>`;
                                            ul.appendChild(li);
                                        });
                                    }
                                    $('.contents').appendChild(ul);
                                    let nextPage = false;
                                    let prevPage = false;
                                    if (data.next_page) {
                                        nextPage = data.next_page;
                                    }
                                    if (data.prev_page) {
                                        prevPage = data.prev_page;
                                    }
                                    let pp = document.createElement('p');
                                    pp.classList.add('pagination');
                                    pp.innerHTML = ``
                                        + `${data.prev_page ? `<a href="javascript:void(0)" class="prev btn" data-page="${data.prev_page}">Previous</a>` : ''}`
                                        + `${data.next_page ? `<a href="javascript:void(0)" class="next btn" data-page="${data.next_page}">Next</a>` : ''}`;
                                    $('.contents').appendChild(pp);
                                }
                                resolve(data);
                            });
                        }
                    });
                });
            });
        });
    }

    function decrypt(data) {
        return new Promise(function(resolve, reject) {
            openpgp.decrypt({
                message: openpgp.message.readArmored(data),
                publicKeys: [gpgOpts.publicKeyObj],
                privateKeys: gpgOpts.privateKeyObj
            }).then(function(val) {
                resolve(val);
            });
        });
    }

    $('.export').addEventListener('click', function() {
        fetchRows(1);
    });

    $('.contents').addEventListener('click', function(ev) {
        if (ev.target.parentNode && ev.target.parentNode.classList.contains('row')) {
            if (ev.target.parentNode.querySelector('.hidden')) {
                ev.target.parentNode.querySelector('.hidden').classList.remove('hidden');
                ev.target.innerText = 'Hide';
            } else {
                ev.target.parentNode.querySelector('span').classList.add('hidden');
                ev.target.innerText = 'View';
            }
        }
        if (ev.target.classList.contains('next') || ev.target.classList.contains('prev')) {
            fetchRows(parseInt(ev.target.getAttribute('data-page')));
        }
    });
})();
