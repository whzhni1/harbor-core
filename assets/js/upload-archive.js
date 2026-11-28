(function (global) {
    'use strict';

    var HF = global.HarborFile = global.HarborFile || {};

    global.addEventListener('beforeunload', function (event) {
        if (HF.state && HF.state.uploading) {
            event.preventDefault();
            event.returnValue = '';
        }
    });

    function available() {
        return typeof global.CompressionStream === 'function' &&
            typeof global.ReadableStream === 'function' &&
            typeof global.Blob === 'function' &&
            typeof global.TextEncoder === 'function' &&
            typeof global.fetch === 'function';
    }

    function sftpAvailable() {
        return typeof global.Blob === 'function' && typeof global.fetch === 'function';
    }

    function octal(value, width) {
        return ('0000000000' + Math.max(0, Math.floor(value)).toString(8)).slice(-width);
    }

    function writeString(bytes, offset, text) {
        var encoded = new TextEncoder().encode(text);
        for (var i = 0; i < encoded.length && offset + i < bytes.length; i++)
            bytes[offset + i] = encoded[i];
    }

    function tarHeader(name, size, mtime, mode, type) {
        var block = new Uint8Array(512);
        writeString(block, 0, name);
        writeString(block, 100, octal(mode, 7) + '\0');
        writeString(block, 108, octal(0, 7) + '\0');
        writeString(block, 116, octal(0, 7) + '\0');
        writeString(block, 124, octal(size, 11) + '\0');
        writeString(block, 136, octal(mtime, 11) + '\0');
        for (var i = 148; i < 156; i++) block[i] = 32;
        writeString(block, 156, type);
        writeString(block, 257, 'ustar\0');
        writeString(block, 263, '00');
        var sum = 0;
        for (var j = 0; j < 512; j++) sum += block[j];
        writeString(block, 148, octal(sum, 6) + '\0 ');
        return block;
    }

    function padLength(size) {
        var remainder = size % 512;
        return remainder ? 512 - remainder : 0;
    }

    function splitPath(relative) {
        var clean = String(relative || '').replace(/\\/g, '/').replace(/^\.?\/+/, '');
        var parts = [];
        var invalid = false;
        clean.split('/').forEach(function (part) {
            if (!part || part === '.') return;
            if (part === '..' || /[\x00-\x1f\x7f]/.test(part)) { invalid = true; return; }
            parts.push(part);
        });
        if (invalid || !parts.length) return null;
        var result = parts.join('/');
        // The ustar name field is 100 bytes, not 100 JavaScript characters.
        if (new TextEncoder().encode(result).length > 100) return null;
        return result;
    }

    function buildEntries(batch) {
        var entries = [];
        var seen = Object.create(null);
        var used = Object.create(null);
        var invalid = false;

        function addDirectory(path) {
            var clean = splitPath(path);
            if (!clean) { invalid = true; return; }
            if (seen[clean]) return;
            var parts = clean.split('/');
            for (var i = 1; i <= parts.length; i++) {
                var current = parts.slice(0, i).join('/');
                if (seen[current]) continue;
                if (new TextEncoder().encode(current + '/').length > 100) { invalid = true; return; }
                seen[current] = true;
                entries.push({ name: current + '/', type: '5', size: 0, mode: 493 });
            }
        }

        function resolveName(relative) {
            var clean = splitPath(relative);
            if (!clean) return null;
            if (!used[clean]) { used[clean] = 1; return clean; }
            var parts = clean.split('/');
            var name = parts.pop();
            var dir = parts.length ? parts.join('/') + '/' : '';
            var dot = name.lastIndexOf('.');
            var base = dot > 0 ? name.slice(0, dot) : name;
            var extension = dot > 0 ? name.slice(dot) : '';
            var counter = 1;
            var candidate;
            do {
                candidate = dir + base + ' (' + counter + ')' + extension;
                counter++;
            } while (used[candidate]);
            if (!splitPath(candidate)) return null;
            used[candidate] = 1;
            return candidate;
        }

        (batch.directories || []).forEach(addDirectory);
        var plan = [];
        (batch.files || []).forEach(function (file) {
            var name = resolveName(HF.upload_relative_path(file));
            if (!name || !Number.isSafeInteger(Number(file.size)) || Number(file.size) < 0 || Number(file.size) > 8589934591) { invalid = true; return; }
            var parts = name.split('/');
            parts.pop();
            if (parts.length) addDirectory(parts.join('/'));
            plan.push({ name: name, file: file });
        });
        plan.forEach(function (item) {
            entries.push({
                name: item.name,
                type: '0',
                size: Number(item.file.size || 0),
                mode: 420,
                file: item.file,
                mtime: Math.floor((item.file.lastModified || Date.now()) / 1000)
            });
        });
        return { entries: entries, plan: plan, valid: !invalid };
    }

    var PART_SIZE = 4 * 1024 * 1024;

    function nextHeader(state) {
        if (state.index >= state.entries.length) return null;
        var entry = state.entries[state.index];
        if (entry.type === '5') {
            state.index++;
            return { bytes: tarHeader(entry.name, 0, Math.floor(Date.now() / 1000), entry.mode, '5') };
        }
        state.remaining = entry.size;
        state.padLeft = padLength(entry.size);
        state.reader = entry.file.stream().getReader();
        state.index++;
        return { bytes: tarHeader(entry.name, entry.size, entry.mtime, entry.mode, '0') };
    }

    function Packer(entries) {
        this.entries = entries;
        this.state = { entries: entries, index: 0, reader: null, remaining: 0, padLeft: 0 };
        this.queue = [];
        this.queued = 0;
        this.done = false;
    }

    Packer.prototype.fill = function fill(target) {
        var self = this;
        var state = this.state;
        return (async function () {
            while (!self.done && self.queued < target) {
                if (state.reader) {
                    var chunk = await state.reader.read();
                    if (!chunk.done) {
                        if (chunk.value.length > state.remaining) throw new Error('Upload file size changed');
                        state.remaining -= chunk.value.length;
                        self.queue.push(chunk.value);
                        self.queued += chunk.value.length;
                        continue;
                    }
                    if (state.remaining !== 0) throw new Error('Upload file size changed');
                    state.reader = null;
                    if (state.padLeft) {
                        self.queue.push(new Uint8Array(state.padLeft));
                        self.queued += state.padLeft;
                        state.padLeft = 0;
                    }
                    continue;
                }
                var header = nextHeader(state);
                if (!header) {
                    self.queue.push(new Uint8Array(1024));
                    self.queued += 1024;
                    self.done = true;
                    break;
                }
                self.queue.push(header.bytes);
                self.queued += header.bytes.length;
            }
        })();
    };

    Packer.prototype.drain = function drain(limit) {
        var parts = [];
        var total = 0;
        while (this.queue.length && total < limit) {
            var piece = this.queue.shift();
            if (!(piece && typeof piece.length === 'number')) {
                throw new Error('Upload packer produced an invalid block');
            }
            var room = limit - total;
            if (piece.length > room) {
                parts.push(piece.subarray(0, room));
                this.queue.unshift(piece.subarray(room));
                total += room;
            } else {
                parts.push(piece);
                total += piece.length;
            }
        }
        this.queued -= total;
        return new Blob(parts);
    };

    function compress(blob) {
        if (typeof global.CompressionStream !== 'function') {
            return Promise.reject(new Error('gzip compression is unavailable'));
        }
        try {
            return new Response(blob.stream().pipeThrough(new global.CompressionStream('gzip'))).blob()
                .catch(function () { throw new Error('gzip compression failed'); });
        } catch (error) {
            return Promise.reject(new Error('gzip compression failed'));
        }
    }

    HF.upload_batch_archive_supported = function upload_batch_archive_supported(batch) {
        if (!batch) return false;
        if (!available()) return false;
        var files = batch.files || [];
        if (!files.length) return false;
        return buildEntries(batch).valid;
    };

    function postChunk(url, blob, onprogress) {
        return new Promise(function (resolve, reject) {
            var xhr = new XMLHttpRequest();
            postChunk._current = xhr;
            xhr.open('POST', url, true);
            xhr.withCredentials = true;
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            if (onprogress && xhr.upload) {
                xhr.upload.onprogress = function (event) {
                    if (event.lengthComputable) onprogress(event.loaded, event.total);
                };
            }
            xhr.onload = function () {
                var text = xhr.responseText || '';
                var payload = null;
                try { payload = JSON.parse(text); } catch (error) {}
                resolve({ status: xhr.status, payload: payload, text: text });
            };
            xhr.onerror = function () { reject(new Error(HF.labels.upload_failed)); };
            xhr.onabort = function () { reject(new Error('aborted')); };
            xhr.send(blob || new Blob([]));
        });
    }

    function failureOf(result, fallback) {
        var payload = result.payload;
        return (payload && payload.message) || result.text || fallback || HF.labels.upload_failed;
    }

    function joinRemote(dir, rel) {
        return String(dir).replace(/\/+$/, '') + '/' + rel;
    }

    HF.upload_sftp_batch = function upload_sftp_batch(batch, conflict_map) {
        var owner = HF.file_context(batch);
        if (!owner.device_id) return false;
        if (!sftpAvailable()) return false;
        var files = batch.files || [];
        if (!files.length) return false;
        for (var i = 0; i < files.length; i++) {
            if (!splitPath(HF.upload_relative_path(files[i]))) return false;
        }
        var total = Number(batch.total_size || 0) || 1;
        var target = batch.target_dir;
        var io = HF.file_io(batch);
        var sent = 0;
        var lastReport = 0;
        var stopped = false;
        var cancelCurrent = null;

        HF.state.upload_cancel_action = function() {
            if (stopped) return;
            stopped = true;
            HF.state.upload_cancelled = true;
            if (postChunk._current && postChunk._current.abort) postChunk._current.abort();
            if (cancelCurrent) cancelCurrent();
        };

        function report(force, loaded) {
            var now = Date.now();
            if (!force && lastReport && now - lastReport < 80) return;
            lastReport = now;
            var bytes = loaded == null ? sent : loaded;
            HF.update_upload_speed(bytes);
            HF.set_upload_panel(
                HF.labels.uploading,
                HF.labels.upload_to + ': ' + target,
                force ? 99 : Math.min(99, (bytes / total) * 100), '', bytes, total
            );
        }

        function stop(message) {
            if (HF.state.upload_cancelled) return;
            stopped = true;
            cancelCurrent = null;
            HF.state.upload_cancel_action = null;
            HF.set_upload_controls(false, false);
            HF.state.uploading = false;
            HF.update_toolbar();
            HF.fail_upload_batch(message);
        }

        function sendFile(file, index) {
            var rel = HF.upload_relative_path(file);
            var destination = joinRemote(target, rel);
            var overwrite = !!(conflict_map && conflict_map[rel]);
            var base = io.requestURL('api_upload_sftp', destination, {
                rpc_action: 'upload',
                target_dir: target
            }) + '&overwrite=' + (overwrite ? '1' : '0') +
                '&preserve_permissions=' + (batch.preserve_permissions === false ? '0' : '1') +
                '&upload_size=' + Number(file.size || 0) +
                '&upload_mtime=' + Number(file.lastModified || 0);
            var blob = file;
            var offset = 0;
            var session = null;
            var pausedTemp = false;
            var finishing = false;
            var attempts = 0;
            cancelCurrent = function() {
                if (session) {
                    postChunk(base + '&upload_session=' + encodeURIComponent(session) + '&abort=1', new Blob([])).catch(function() {});
                    session = null;
                } else if (pausedTemp) {
                    postChunk(base, new Blob([])).then(function(result) {
                        var id = result.payload && result.payload.data && result.payload.data.upload_session;
                        if (id) return postChunk(base + '&upload_session=' + encodeURIComponent(id) + '&abort=1', new Blob([]));
                        return null;
                    }).catch(function() {});
                    pausedTemp = false;
                }
            };

            function pauseAtBoundary() {
                if (!session) return HF.wait_upload_resume();
                var previous = session;
                return postChunk(base + '&upload_session=' + encodeURIComponent(previous) + '&pause=1', new Blob([]))
                    .then(function(result) {
                        if (result.status < 200 || result.status >= 300 || !result.payload || result.payload.code !== 0) {
                            throw new Error(failureOf(result));
                        }
                        session = null;
                        pausedTemp = true;
                    })
                    .catch(function() {})
                    .then(HF.wait_upload_resume)
                    .then(function() {});
            }

            function step() {
                if (stopped) return Promise.resolve();
                if (HF.state.upload_paused) {
                    return pauseAtBoundary().then(function() {
                        if (stopped) return null;
                        return session ? step() : start();
                    });
                }
                if (offset >= blob.size) {
                    finishing = true;
                    return postChunk(base + '&upload_session=' + encodeURIComponent(session) + '&finish=1', new Blob([]))
                        .then(function (result) {
                            if (result.status < 200 || result.status >= 300 || !result.payload || result.payload.code !== 0) {
                                throw new Error(failureOf(result));
                            }
                            return null;
                        });
                }
                var slice = blob.slice(offset, Math.min(offset + PART_SIZE, blob.size));
                HF.begin_upload_data(batch, sent);
                return postChunk(base + '&upload_session=' + encodeURIComponent(session), slice, function (loaded) {
                    report(false, sent + loaded);
                }).then(function (result) {
                        if (result.status < 200 || result.status >= 300 || !result.payload || result.payload.code !== 0) {
                            throw new Error(failureOf(result));
                        }
                        HF.stop_upload_activity();
                        offset = Math.min(offset + PART_SIZE, blob.size);
                        sent += slice.size;
                        report(true, sent);
                        return step();
                    });
            }

            function killPrevious() {
                if (!session) return Promise.resolve();
                var previous = session;
                session = null;
                return postChunk(base + '&upload_session=' + encodeURIComponent(previous) + '&pause=1', new Blob([]))
                    .then(function() { pausedTemp = true; })
                    .catch(function () { return null; });
            }

            function start() {
                return HF.wait_upload_resume().then(killPrevious).then(function () {
                    return postChunk(base, new Blob([]));
                }).then(function (result) {
                    if (result.status < 200 || result.status >= 300 || !result.payload || result.payload.code !== 0) {
                        throw new Error(failureOf(result));
                    }
                    session = result.payload.data.upload_session;
                    pausedTemp = false;
                    var received = Number(result.payload.data.received || 0);
                    offset = received;
                    if (received > sent) sent = received;
                    return step();
                });
            }

            function attempt() {
                attempts += 1;
                return start().catch(function (error) {
                    if (stopped) return null;
                    // A finish request may have committed even when its reply
                    // was lost. Never re-upload automatically in that state.
                    if (finishing) throw new Error(HF.tr('Upload outcome is unknown; check the destination before retrying') + ': ' + ((error && error.message) || ''));
                    if (attempts >= 5) throw error;
                    return new Promise(function (resolve) {
                        setTimeout(resolve, Math.min(5000, 400 * Math.pow(2, attempts - 1)));
                    }).then(attempt);
                });
            }

            return attempt().then(function () {
                cancelCurrent = null;
                return index;
            });
        }

        function next(index) {
            if (stopped || HF.state.upload_cancelled || index >= files.length) return Promise.resolve();
            return HF.wait_upload_resume().then(function() {
                if (stopped || HF.state.upload_cancelled) return null;
                return sendFile(files[index], index).then(function() { return next(index + 1); });
            });
        }

        HF.set_upload_panel(HF.labels.uploading, HF.labels.upload_to + ': ' + target, 0, '', 0, total);

        next(0).then(function () {
            if (stopped) return;
            HF.stop_upload_activity();
            report(true);
            HF.state.uploading = false;
            HF.state.upload_cancel_action = null;
            HF.set_upload_controls(false, false);
            HF.update_toolbar();
            HF.set_upload_panel(
                HF.labels.upload_complete,
                files.length + ' ' + HF.labels.file +
                    ((batch.directories || []).length ? ' \u00b7 ' + batch.directories.length + ' ' + HF.labels.folder : ''),
                100, 'success', total, total
            );
            HF.refresh_after_write();
            if (HF.maybe_autoclose_upload) HF.maybe_autoclose_upload();
        }).catch(function (error) {
            if (stopped) return;
            stop((error && error.message) || HF.labels.upload_failed);
        });
        return true;
    };

    HF.upload_batch_archive = function upload_batch_archive(batch, conflict_map) {
        var built = buildEntries(batch);
        if (!built.valid || !built.entries.length) return false;
        var overwrite = false;
        (batch.files || []).forEach(function (file) {
            if (conflict_map && conflict_map[HF.upload_relative_path(file)]) overwrite = true;
        });
        if ((batch.selected_directory_conflicts || []).length) overwrite = true;
        var total = Number(batch.total_size || 0) || 1;
        var base = HF.file_io(batch).requestURL('api_upload_archive', batch.target_dir, {
            rpc_action: 'upload',
            target_dir: batch.target_dir
        }) + '&overwrite=' + (overwrite ? '1' : '0') +
            '&preserve_permissions=' + (batch.preserve_permissions === false ? '0' : '1');
        var sent = 0;
        var lastReport = 0;
        var packer = new Packer(built.entries);
        var session = null;
        var stopped = false;
        var finishing = false;

        HF.state.upload_cancel_action = function() {
            stopped = true;
            if (postChunk._current && postChunk._current.abort) postChunk._current.abort();
            if (session) {
                postChunk(base + '&upload_session=' + encodeURIComponent(session) + '&abort=1', new Blob([])).catch(function() {});
                session = null;
            }
        };

        function report(force, loaded) {
            var now = Date.now();
            if (!force && lastReport && now - lastReport < 80) return;
            lastReport = now;
            var bytes = loaded == null ? sent : loaded;
            HF.update_upload_speed(bytes);
            HF.set_upload_panel(
                HF.labels.uploading,
                HF.labels.upload_to + ': ' + batch.target_dir,
                force ? 99 : Math.min(99, (bytes / total) * 100), '', bytes, total
            );
        }

        function fail(message) {
            if (stopped || HF.state.upload_cancelled) return;
            if (session) {
                postChunk(base + '&upload_session=' + encodeURIComponent(session) + '&abort=1', new Blob([])).catch(function () {});
                session = null;
            }
            // Before finish the server only stages bytes; after finish it may
            // already have written files, so never retry automatically.
            if (!finishing && HF.upload_sftp_batch && /tar|gzip|connection|broken pipe|reset|refused|Cannot write to the device|Remote command failed/i.test(String(message || ''))) {
                HF.upload_directory_next(batch, conflict_map, 0, function () {
                    if (HF.state.upload_cancelled) return;
                    if (HF.upload_sftp_batch(batch, conflict_map)) return;
                    HF.fail_upload_batch(message);
                });
                return;
            }
            HF.state.uploading = false;
            HF.update_toolbar();
            HF.fail_upload_batch(message);
        }

        function finish() {
            finishing = true;
            HF.stop_upload_activity();
            report(true);
            return postChunk(base + '&upload_session=' + encodeURIComponent(session) + '&finish=1', new Blob([]))
                .then(function (result) {
                    if (result.status < 200 || result.status >= 300 || !result.payload || result.payload.code !== 0) {
                        throw new Error(failureOf(result));
                    }
                    HF.state.uploading = false;
                    HF.state.upload_cancel_action = null;
                    HF.set_upload_controls(false, false);
                    HF.update_toolbar();
                    HF.set_upload_panel(
                        HF.labels.upload_complete,
                        batch.files.length + ' ' + HF.labels.file +
                            ((batch.directories || []).length ? ' · ' + batch.directories.length + ' ' + HF.labels.folder : ''),
                        100, 'success', total, total
                    );
                    HF.refresh_after_write();
                    if (HF.maybe_autoclose_upload) HF.maybe_autoclose_upload();
                });
        }

        function sendParts() {
            if (stopped || HF.state.upload_cancelled) return Promise.resolve();
            if (packer.done && !packer.queue.length) return finish();
            return packer.fill(PART_SIZE).then(function () {
                var part = packer.drain(PART_SIZE);
                if (!part.size) {
                    if (packer.done) return finish();
                    throw new Error('Upload packer stalled');
                }
                return compress(part).then(function (packed) {
                    HF.begin_upload_data(batch, sent);
                    return postChunk(base + '&upload_session=' + encodeURIComponent(session), packed, function (loaded) {
                        var approx = packed.size > 0 ? sent + (part.size * loaded / packed.size) : sent + loaded;
                        report(false, approx);
                    });
                }).then(function (result) {
                    if (result.status < 200 || result.status >= 300 || !result.payload || result.payload.code !== 0) {
                        throw new Error(failureOf(result));
                    }
                    HF.stop_upload_activity();
                    sent += part.size;
                    report(true, sent);
                    return sendParts();
                });
            });
        }

        HF.set_upload_panel(HF.labels.uploading, HF.labels.upload_to + ': ' + batch.target_dir, 0, '', 0, total);

        var initManifest = new Blob([JSON.stringify({
            preserve_paths: batch.preserve_permissions === false ? [] : (batch.preserve_paths || [])
        })], { type: 'application/json' });
        postChunk(base, initManifest).then(function (result) {
            if (result.status < 200 || result.status >= 300 || !result.payload || result.payload.code !== 0) {
                throw new Error(failureOf(result));
            }
            session = result.payload.data.upload_session;
            return sendParts();
        }).catch(function (error) {
            var message = (error && error.message) || HF.labels.upload_failed;
            if (finishing && /network|fetch|connection|reset|timeout/i.test(String(message))) {
                message = HF.tr('Upload outcome is unknown; check the destination before retrying');
            }
            fail(message);
        });
        return true;
    };

})(typeof window !== 'undefined' ? window : this);
