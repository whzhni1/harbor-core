(function (HF) {
    var devices = new Map(), capacities = new Map(), lastPaths = Object.create(null);
    var settingsSequence = 0, deviceSequence = 0, taskSequence = 0;
    var capacityQueue = [], capacityActive = 0;
    var devicesLoaded = false, devicesLoading = false, installations = new Map();
    try { lastPaths = JSON.parse(localStorage.getItem('harbor_file_pro_remote_paths') || '{}') || {}; } catch (e) {}
    function label(key) { return HF.labels['remote_' + key] || key; }
    function inputPlaceholder(key) {
        return { name: label('name_placeholder'), host: '192.168.1.1 / router.example.com', port: '22', username: 'root', password: label('password_placeholder') }[key];
    }
    function activeDevice() { return HF.state.current && HF.state.current.device_id || ''; }
    var devModePromise = null;
    function devModeEnabled() {
        if (!devModePromise) {
            devModePromise = fetch('/api/v1/version', { credentials: 'same-origin', cache: 'no-store' }).then(function(response) {
                return response.json();
            }).then(function(data) {
                return !!(data && data.data && data.data.dev_mode);
            }).catch(function() {
                return false;
            });
        }
        return devModePromise;
    }
    function remoteSettingsActive() {
        return ['remote', 'remote_connection'].some(function(name) {
            var panel = document.getElementById('fm_settings_panel_' + name);
            return panel && panel.classList.contains('active');
        });
    }
    function nameOf(id) { return id ? (devices.get(id) || {}).name || id : HF.labels.this_pc; }
    HF.remote_device_name = nameOf;
    HF.remote_owner_current = function(owner) {
        var id = owner && owner.device_id || '', revision = owner && owner.device_revision || '';
        if (!id) return !revision;
        var device = devices.get(id);
        return !!(device && revision && device.revision === revision);
    };
    function button(text, action, primary) {
        var node = HF.Util.createElement('button', 'fm-dialog-action' + (primary ? ' primary' : ''), text);
        node.type = 'button'; node.addEventListener('click', action); return node;
    }
    function remember(id, path) {
        lastPaths[id] = path;
        try { localStorage.setItem('harbor_file_pro_remote_paths', JSON.stringify(lastPaths)); } catch (e) {}
    }
    function request(action, data, quiet) {
        return new Promise(function(resolve, reject) {
            var requestUrl = HF.api.list;
            HF.Util.ajax({
                url: requestUrl, type: 'POST', dataType: 'json',
                timeout: action === 'rpc' || action === 'agent_prepare' ? 120000 : action === 'start' || action === 'check' || action === 'install_stat' ? 75000 : action === 'list' || action === 'capacity' || action === 'tools' || action === 'dependency' || action === 'tool_check' ? 45000 : 15000,
                data: Object.assign({}, data || {}, { remote_action: action, sessionid: HF.sessionid || (window.HarborIO && HarborIO.getSessionID()) || '' }),
                success: function(res) {
                    if (res && res.code === 0) { resolve(res.data || {}); return; }
                    if (HF.retry_system_access(requestUrl, data, res, function() {
                        request(action, data, quiet).then(resolve, reject);
                    }, function() {
                        var denied = new Error(res && res.message || HF.labels.request_failed);
                        denied.data = res && res.data;
                        reject(denied);
                    })) return;
                    var error = new Error(res && res.message || HF.labels.request_failed);
                    error.data = res && res.data;
                    error.code = res && res.code || 1;
                    error.uncertain = !!(error.data && error.data.outcome_unknown === true);
                    if (res && res.code === 11 && error.data && !quiet) {
                        var info = error.data;
                        HF.confirm_window({ title: label('host_key'), message: nameOf(info.device_id) + ' · ' + info.host + ':' + info.port + '\n' + info.fingerprint + '\n' + label('verify') }).then(function(yes) {
                            if (!yes) { reject(error); return; }
                            request('trust', { device_id: info.device_id, challenge: info.challenge }, true).then(function() {
                                request(action, data, true).then(resolve, reject);
                            }, reject);
                        });
                        return;
                    }
                    reject(error);
                },
                error: function(xhr) {
                    if (window.console && console.warn) console.warn('Harbor remote request failed', action, xhr && xhr.status, xhr && xhr.statusText);
                    var response = HF.response_json(xhr);
                    if (action === 'rpc' && response && response.code === 0 && response.data && typeof response.data.code === 'number') response = response.data;
                    var message = response && response.message || HF.batch_error_message(xhr, HF.labels.request_failed);
                    if ((!response || !response.message) && xhr && xhr.status) message += ' (HTTP ' + xhr.status + ')';
                    var error = new Error(message);
                    error.code = response && typeof response.code === 'number' && response.code !== 0 ? response.code : 1;
                    error.data = response && response.data;
                    error.uncertain = !(error.data && error.data.missing_tool && error.data.dependency_preflight === true && error.data.outcome_unknown !== true); reject(error);
                }
            });
        });
    }
    function requiredRequest(action, data) {
        data = Object.assign({}, data);
        var attempted = new Set();
        var owners = ['device', 'source', 'target'].map(function(key) {
            return { device_id: data[key === 'device' ? 'device_id' : key + '_device'] || '', device_revision: data[key === 'device' ? 'device_revision' : key + '_revision'] || '' };
        });
        function retry() {
            for (var i = 0; i < owners.length; i++) {
                var owner = owners[i], device = devices.get(owner.device_id);
                if (owner.device_id && (!device || !owner.device_revision || device.revision !== owner.device_revision)) return Promise.reject(new Error(label('stale_device')));
            }
            return request(action, data).catch(function(error) {
                var info = error.data;
                if (!info || error.stopFallback) throw error;
                if (action === 'agent_prepare' && !info.dependency_preflight && info.stat_missing) {
                    if (info.missing_tool && info.missing_tool !== 'stat') throw error;
                    info = Object.assign({}, info, { missing_tool: 'stat', dependency_preflight: true, device_id: info.device_id === undefined ? data.device_id : info.device_id });
                } else if (info.dependency_preflight !== true || info.outcome_unknown === true) throw error;
                var tool = info.missing_tool;
                if (!tool || !/^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$/.test(tool)) throw error;
                var deviceId = typeof info.device_id === 'string' ? info.device_id : (typeof data.device_id === 'string' ? data.device_id : '');
                var deviceRevision = typeof info.device_revision === 'string' ? info.device_revision : (typeof data.device_revision === 'string' ? data.device_revision : '');
                info = Object.assign({}, info, { device_id: deviceId, device_revision: deviceRevision });
                var owner = HF.file_context(info);
                if (owner.device_id && !owners.some(function(value) { return value.device_id === owner.device_id && value.device_revision === owner.device_revision; })) throw error;
                if (!owner.device_id && owner.device_revision) throw error;
                var key = JSON.stringify([owner.device_id, owner.device_revision, tool]);
                if (attempted.has(key)) throw error;
                attempted.add(key);
                error.stopFallback = true;
                return HF.ensure_dependency(tool, owner).then(function(ready) {
                    if (!ready) throw error;
                    return retry();
                });
            });
        }
        return retry();
    }
    HF.remote_request = request;
    HF.require_remote_request = requiredRequest;
    HF.check_dependency = function(name, target, evidence) {
        var owner = HF.file_context(target || {});
        function valid() {
            if (owner.device_id) {
                var device = devices.get(owner.device_id);
                if (!device || !owner.device_revision || device.revision !== owner.device_revision) throw new Error(label('stale_device'));
            } else if (owner.device_revision) throw new Error(label('stale_device'));
        }
        return Promise.resolve().then(function() {
            valid();
            if (evidence) return evidence;
            return request('tool_check', Object.assign({ tool: name }, owner));
        }).then(function(data) {
            valid();
            if (!data || data.device_id !== undefined && data.device_id !== owner.device_id ||
                data.device_revision !== undefined && data.device_revision !== owner.device_revision) throw new Error(label('stale_device'));
            var missing = data.missing_tool === name || name === 'stat' && data.stat_missing;
            var sftpDisabled = data.sftp === 'disabled';
            var available = missing || sftpDisabled ? false : data.available;
            var installed = missing || sftpDisabled ? false : data.installed;
            if (installed === 0 || installed === 1) installed = !!installed;
            if (typeof available !== 'boolean' || typeof installed !== 'boolean') throw new Error(HF.labels.request_failed);
            var info = Object.assign({}, data, owner, { tool: data.tool || name, package_name: data.package_name || name, installed: installed, available: available });
            return info;
        });
    };
    HF.dependency_install_options = function(info, owner) {
        var tool = info.tool;
        if (owner.device_id && tool === 'stat') return {
            start: function(done, failed) {
                var device = devices.get(owner.device_id);
                if (!device || device.revision !== owner.device_revision) { failed(new Error(label('stale_device'))); return; }
                request('install_stat', owner).then(done, failed);
            },
            status: function(task_id, done, failed) { request('status', { task_id: task_id }, true).then(done, failed); }
        };
        return {};
    };
    HF.remote_unavailable = function() { HF.set_warning_status(label('unavailable')); };
    function loadDevices() {
        var sequence = ++deviceSequence; devicesLoading = true;
        var add = document.getElementById('fm_remote_add_device');
        if (add) add.disabled = true;
        return request('devices').then(function(data) {
            if (sequence === deviceSequence) {
                devicesLoaded = true;
                if (add) add.disabled = false;
                devices.clear();
                (data.devices || []).forEach(function(d) { devices.set(d.id, d); });
                capacities.forEach(function(entry, id) { if (!currentCapacity(entry)) capacities.delete(id); });
                preparedFiles.forEach(function(entry, id) { if (!devices.has(id) || devices.get(id).revision !== entry.revision) invalidateFiles(id); });
                HF.render_sidebar();
                if (HF.state.target_picker && HF.configure_target_devices) HF.configure_target_devices(HF.state.target_picker);
                if (activeDevice()) HF.update_toolbar();
            }
            return data;
        }).catch(function(error) { if (sequence === deviceSequence) devicesLoaded = true; throw error; }).finally(function() { if (sequence === deviceSequence) devicesLoading = false; });
    }
    HF.append_remote_navigation = function(sidebar) {
        var active = HF.state.current && HF.state.current.kind === 'remote_devices';
        var heading = HF.create_sidebar_button(label('devices'), 'this_pc', 'fm-nav-heading' + (active ? ' active' : ''), function() { HF.show_remote_devices(true); });
        HF.bind_sidebar_menu(heading, function(x, y) { HF.show_sidebar_settings_menu('remote:', x, y); });
        var list = HF.create_sidebar_section(sidebar, 'remote', heading);
        devices.forEach(function(d) {
            var node = HF.create_sidebar_button(d.name, 'this_pc', 'fm-nav-item fm-nav-drive fm-nav-remote' + (activeDevice() === d.id ? ' active' : ''), function() { HF.open_remote_path(d.id, lastPaths[d.id] || '/', true); });
            HF.bind_sidebar_menu(node, function(x, y) { HF.show_sidebar_settings_menu('remote:' + d.id, x, y); });
            var meta = HF.add_sidebar_meta(node, label('unknown'));
            meta.dataset.remoteCapacity = d.id;
            node.dataset.deviceId = d.id; node.title = d.name; list.appendChild(node);
            HF.bind_drop_target(node, lastPaths[d.id] || '/', d.name, { device_id: d.id, device_revision: d.revision });
            ensureCapacity(d);
        });
        if (!devicesLoaded && !devicesLoading) loadDevices().catch(function() {});
    };
    HF.remote_path_segments = function() {
        var current = HF.state.current;
        if (!current) return null;
        if (current.kind === 'remote_devices') return [{ label: label('devices'), kind: 'remote_devices' }];
        if (!current.device_id) return null;
        var id = current.device_id;
        return [{ label: nameOf(id), path: '/', device_id: id }].concat(HF.directory_segments(current.path, false).map(function(crumb) {
            return Object.assign({}, crumb, { device_id: id });
        }));
    };
    HF.show_remote_devices = function(addHistory) {
        var previous = HF.state.current;
        var sequence = HF.navigation_request = (HF.navigation_request || 0) + 1;
        HF.clear_marquee(); HF.hide_context_menus(); HF.hide_details(); HF.clear_selection();
        HF.state.current = { kind: 'remote_devices' };
        HF.state.current_directory_data = null; HF.state.context_item = null;
        var content = document.getElementById('fm_content'); HF.clear_node(content);
        var header = HF.Util.createElement('div', 'fm-page-header');
        header.appendChild(HF.Util.createElement('h1', 'fm-page-title', label('devices')));
        var add = button(label('add'), openSettings); add.id = 'fm_remote_add_device'; add.disabled = true;
        header.appendChild(add); content.appendChild(header);
        var status = HF.Util.createElement('div', 'fm-remote-status', label('loading')); content.appendChild(status);
        if (addHistory) HF.push_history(HF.state.current);
        HF.render_sidebar(); HF.update_toolbar();
        loadDevices().then(function(data) {
            if (sequence !== HF.navigation_request) return;
            status.textContent = ''; status.hidden = true;
            if (!data.devices.length) { status.textContent = label('add'); status.hidden = false; }
            data.devices.forEach(function(d) {
                var section = HF.Util.createElement('div', 'fm-remote-device');
                section.dataset.remoteDrives = d.id;
                content.appendChild(section);
                ensureCapacity(d);
            });
        }).catch(function(error) { if (sequence === HF.navigation_request) { status.textContent = error.message; status.hidden = false; } });
    };
    function currentCapacity(entry) {
        var d = devices.get(entry.id);
        return capacities.get(entry.id) === entry && d && d.trusted && d.revision === entry.revision && (lastPaths[entry.id] || '/') === entry.path;
    }
    function capacityText(data) {
        function compact(bytes) { return HF.format_size(bytes).replace(/\.0 /, ' ').replace(/ ([KMGT])B$/, '$1').replace(/ B$/, 'B'); }
        return compact(data.used_bytes) + ' / ' + compact(data.total_bytes);
    }
    function paintCapacity(id) {
        var entry = capacities.get(id);
        if (entry && !currentCapacity(entry)) entry = null;
        var device = devices.get(id);
        var name = device && device.name || id;
        var data = entry && entry.data;
        document.querySelectorAll('[data-remote-capacity]').forEach(function(node) {
            if (node.dataset.remoteCapacity !== id) return;
            node.textContent = data ? capacityText(data) : entry && entry.error ? label('failed_connection') : label('unknown');
            node.title = entry && entry.error || '';
        });
        document.querySelectorAll('[data-remote-drives]').forEach(function(node) {
            if (node.dataset.remoteDrives !== id) return;
            HF.clear_node(node);
            var drives = data && Array.isArray(data.drives) ? data.drives : [];
            if (drives.length) {
                HF.render_group(node, name, drives.map(function(drive) {
                    var item = HF.prepare_drive_item(drive);
                    item.device_id = id;
                    item.device_revision = entry.revision;
                    return item;
                }), 'drive');
                return;
            }
            var total = data ? Number(data.total_bytes || 0) : 0;
            var used = data ? Number(data.used_bytes || 0) : 0;
            var item = HF.prepare_drive_item({
                path: lastPaths[id] || '/',
                name: name,
                device: '',
                used_kb: Math.round(used / 1024),
                total_kb: Math.round(total / 1024),
                usage_percent: total > 0 ? Math.min(100, Math.round(used * 100 / total)) : 0
            });
            item.name = name;
            item.device_id = id;
            item.device_revision = entry && entry.revision || '';
            if (!data) {
                item.meta = entry && entry.pending ? label('loading')
                    : entry && entry.error ? label('failed_connection')
                    : label('unknown');
            }
            HF.render_group(node, name, [item], 'drive');
        });
    }
    function pumpCapacities() {
        while (capacityActive < 2 && capacityQueue.length) {
            var entry = capacityQueue.shift();
            if (!currentCapacity(entry)) continue;
            capacityActive++;
            (function(entry) {
                request('capacity', { device_id: entry.id, device_revision: entry.revision, path: entry.path }, true).then(function(data) {
                    if (currentCapacity(entry) && data.device_revision === entry.revision) entry.data = data;
                }, function(error) {
                    if (currentCapacity(entry)) entry.error = error.data && error.data.challenge ? '' : error.message;
                }).finally(function() {
                    entry.pending = false; entry.time = Date.now(); capacityActive--;
                    if (currentCapacity(entry)) paintCapacity(entry.id);
                    pumpCapacities();
                });
            })(entry);
        }
    }
    function ensureCapacity(d) {
        var entry = capacities.get(d.id);
        if (entry && !currentCapacity(entry)) { capacities.delete(d.id); entry = null; }
        if (d.trusted && (!entry || !entry.pending && Date.now() - entry.time >= 60000)) {
            entry = { id: d.id, revision: d.revision, path: lastPaths[d.id] || '/', pending: true, time: Date.now(), data: entry && entry.data };
            capacities.set(d.id, entry); capacityQueue.push(entry); pumpCapacities();
        }
        paintCapacity(d.id);
    }
    function saveCapacity(id, data) {
        capacities.set(id, { id: id, revision: data.device_revision, path: lastPaths[id] || '/', data: data, time: Date.now() });
        paintCapacity(id);
    }
    HF.address_devices = function address_devices() {
        return Array.from(devices.values()).filter(function(device) { return !!device && !!device.name; }).map(function(device) {
            return { id: device.id, name: device.name };
        });
    };

    HF.address_devices_ready = function address_devices_ready() {
        return devicesLoaded;
    };

    HF.address_devices_reload = function address_devices_reload(callback) {
        if (devicesLoaded) {
            if (callback) callback();
            return;
        }
        loadDevices().then(function() { if (callback) callback(); }).catch(function() { if (callback) callback(); });
    };

    HF.remote_last_path = function remote_last_path(id) {
        return lastPaths[id] || '/';
    };

    HF.read_remote_directory = function(id, path, current) {
        var d = devices.get(id);
        if (!d) return Promise.reject(new Error(label('unavailable')));
        var revision = d.revision;
        return fileRequest({ device_id: id, device_revision: revision }, 'list', { path: path }).then(function(res) {
            if (!res || res.code !== 0) throw new Error(res && res.message || HF.labels.request_failed);
            if ((current && !current()) || !devices.has(id) || devices.get(id).revision !== revision) throw new Error(label('stale_device'));
            if (!res.data || !Array.isArray(res.data.items) || typeof res.data.path !== 'string') throw new Error(HF.labels.request_failed);
            var data = Object.assign({}, res.data, { device_revision: revision, device_name: devices.get(id).name });
            if (data.used_bytes === undefined) data.used_bytes = Math.max(0, Number(data.total_bytes || 0) - Number(data.available_bytes || 0));
            return data;
        });
    };
    HF.open_remote_path = function(id, path, addHistory, selectPath) {
        var previous = HF.state.current;
        var sequence = HF.navigation_request = (HF.navigation_request || 0) + 1;
        HF.clear_marquee(); HF.hide_context_menus(); HF.hide_details();
        var content = document.getElementById('fm_content');
        content.querySelectorAll('.fm-remote-loading').forEach(function(node) { node.remove(); });
        var loading = HF.Util.createElement('span', 'fm-remote-loading', label('loading'));
        (content.querySelector('.fm-page-header') || content).appendChild(loading);
        var ready = devices.has(id) ? Promise.resolve() : loadDevices();
        ready.then(function() { return HF.ensure_system_access(path, id); }).then(function(allowed) {
            if (!allowed || sequence !== HF.navigation_request) return null;
            return HF.read_remote_directory(id, path, function() { return sequence === HF.navigation_request; });
        }).then(function(data) {
            if (!data || sequence !== HF.navigation_request || !devices.has(id) || devices.get(id).revision !== data.device_revision) return;
            HF.clear_selection(); HF.state.context_item = null;
            if (activeDevice() !== id || HF.state.sort_path && HF.state.sort_path !== data.path) {
                HF.state.sort_path = ''; HF.state.sort_field = 'name'; HF.state.sort_order = 'asc';
            }
            data.device_id = id;
            if (data.device_name) devices.set(id, Object.assign({}, devices.get(id), { id: id, name: data.device_name, revision: data.device_revision, trusted: true }));
            data.items = (data.items || []).filter(function(item) { return HF.state.preferences.show_hidden_files === 1 || !item.hidden; }).map(function(item) {
                return Object.assign({}, item, { device_id: id, device_revision: data.device_revision });
            });
            HF.state.current = Object.assign({ kind: 'directory', device_id: id }, data);
            delete HF.state.current.items;
            HF.state.current_directory_data = data;
            remember(id, data.path); saveCapacity(id, data);
            HF.render_directory(data);
            if (selectPath) HF.select_rendered_item_by_path(selectPath);
            if (addHistory) HF.push_history(HF.state.current);
            HF.render_sidebar(); HF.update_toolbar();
        }).catch(function(error) { if (sequence === HF.navigation_request) HF.set_error_status(error.message); }).finally(function() { loading.remove(); });
    };
    HF.open_remote_settings = function(device_id) {
        HF.load_preferences(function() {
            var host = document.getElementById('fm_remote_settings');
            host._openAdd = !device_id;
            HF.populate_settings_dialog(); HF.set_settings_tab('remote'); HF.open_modal('fm_settings_dialog');
            if (device_id) {
                var tries = 0;
                var timer = setInterval(function() {
                    var edit = host._editButtons && host._editButtons.get(device_id);
                    if (edit) {
                        clearInterval(timer);
                        edit.click();
                    } else if (++tries > 40) {
                        clearInterval(timer);
                    }
                }, 50);
            }
        });
    };
    function openSettings() {
        HF.open_remote_settings(null);
    }
    function deviceChanged(id, identityChanged) {
        capacities.delete(id); invalidateFiles(id);
        if (identityChanged) {
            remember(id, undefined);
            if (HF.state.clipboard && HF.state.clipboard.device_id === id) HF.state.clipboard = null;
        }
        if (activeDevice() === id && identityChanged || HF.state.current && HF.state.current.kind === 'remote_devices') HF.show_remote_devices(false);
    }
    function updateDeviceEditor(host) {
        var busy = !!host._saving, disabled = busy || !!host._loading;
        Object.keys(host._inputs).forEach(function(key) { host._inputs[key].disabled = busy; });
        host._save.disabled = busy || !!host._loading;
        host._cancel.disabled = busy;
        host._add.disabled = disabled;
        host._add.setAttribute('aria-expanded', !host._form.hidden && !host._deviceId ? 'true' : 'false');
        host._editButtons.forEach(function(button, id) {
            button.disabled = disabled;
            button.setAttribute('aria-expanded', !host._form.hidden && host._deviceId === id ? 'true' : 'false');
        });
    }
    function closeDeviceEditor(host) {
        host._editorSequence = (host._editorSequence || 0) + 1;
        host._deviceId = '';
        host._loading = false;
        host._form.hidden = true;
        host._form.reset();
        Object.keys(host._inputs).forEach(function(key) { host._inputs[key].setCustomValidity(''); });
        host._inputs.password.type = 'password';
        host._inputs.password.required = true;
        Object.keys(host._inputs).forEach(function(key) { host._inputs[key].placeholder = inputPlaceholder(key); });
        host._message.textContent = '';
        host._addBlock.appendChild(host._form);
        host._addBlock.appendChild(host._message);
        updateDeviceEditor(host);
    }
    function editDevice(id) {
        var host = document.getElementById('fm_remote_settings');
        if (host._saving || host._loading) return;
        if (!host._form.hidden && host._deviceId === id) { host._inputs.name.focus(); return; }
        closeDeviceEditor(host);
        var sequence = host._editorSequence;
        host._loading = true; updateDeviceEditor(host);
        host._message.textContent = HF.labels.checking;
        var data = id ? request('get', { id: id }) : Promise.resolve({ id: '', name: '', host: '', port: '', username: '', password: '' });
        data.then(function(d) {
            if (sequence !== host._editorSequence) return;
            var block = id ? host._deviceBlocks.get(id) : host._addBlock;
            if (!block || id && d.id !== id) throw new Error(label('stale_device'));
            host._deviceId = d.id;
            Object.keys(host._inputs).forEach(function(k) { host._inputs[k].value = d[k] === undefined ? '' : d[k]; });
            ['host', 'port', 'username', 'password'].forEach(function(k) {
                host._inputs[k].closest('.fm-settings-row').style.display = '';
                host._inputs[k].required = !id;
            });
            ['name', 'host', 'port', 'username'].forEach(function(k) {
                host._inputs[k].placeholder = id ? label('keep_placeholder') : inputPlaceholder(k);
            });
            host._inputs.password.placeholder = id ? label('keep_placeholder') : label('password_placeholder');
            block.insertBefore(host._form, id ? block.children[1] : host._message);
            host._form.appendChild(host._message);
            host._form.setAttribute('aria-label', id ? label('edit') + ' · ' + d.name : label('add'));
            host._form.hidden = false;
            host._message.textContent = '';
            host._inputs.name.focus();
        }).catch(function(error) {
            if (sequence === host._editorSequence) host._message.textContent = error.message;
        }).finally(function() {
            if (sequence === host._editorSequence) { host._loading = false; updateDeviceEditor(host); }
        });
    }
    function buildConnectionSettings(host) {
        if (host._connectionSettings) return;
        var section = host._connectionSettings = HF.Util.createElement('div', 'fm-remote-connection-settings');
        section.appendChild(HF.Util.createElement('div', 'fm-settings-intro-title', HF.tr('SSH connections')));
        section.appendChild(HF.Util.createElement('div', 'fm-settings-desc', HF.tr('Harbor Core keeps one russh connection per device and reuses it. Idle timeout and channel limits apply to that pool.')));
        function copyLog() {
            var trigger = host._connectionLogButton;
            if (trigger) trigger.disabled = true;
            fetch('/api/v1/ssh_journal', { credentials: 'same-origin' }).then(function(response) {
                return response.json();
            }).then(function(data) {
                var text = JSON.stringify(data, null, 2);
                var done = function() { HF.notify(HF.labels.copied_to_clipboard || HF.tr('Copied to clipboard'), 'success'); };
                var fallback = function() {
                    var area = document.createElement('textarea');
                    area.value = text; area.style.position = 'fixed'; area.style.opacity = '0';
                    document.body.appendChild(area); area.select();
                    var ok = false; try { ok = document.execCommand('copy'); } catch (error) {}
                    document.body.removeChild(area);
                    if (ok) done(); else HF.notify(HF.labels.operation_failed || HF.tr('Copy failed'), 'error');
                };
                if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text).then(done, fallback);
                fallback();
            }).catch(function() {
                HF.notify(HF.labels.operation_failed || HF.tr('Copy failed'), 'error');
            }).finally(function() {
                if (trigger) trigger.disabled = false;
            });
        }
        var logRow = HF.Util.createElement('div', 'fm-settings-row');
        logRow.appendChild(HF.Util.createElement('span', 'fm-settings-label', HF.tr('SSH debug log')));
        var logButton = host._connectionLogButton = button(HF.tr('Copy'), copyLog, false);
        logButton.type = 'button';
        logRow.appendChild(logButton);
        section.appendChild(logRow);
        devModeEnabled().then(function(enabled) {
            if (!enabled && logRow.parentNode) logRow.parentNode.removeChild(logRow);
        });
        function numberRow(labelText, key, min, max, step) {
            var row = HF.Util.createElement('label', 'fm-settings-row');
            row.appendChild(HF.Util.createElement('span', 'fm-settings-label', HF.tr(labelText)));
            var input = document.createElement('input');
            input.type = 'number'; input.className = 'fm-settings-control fm-settings-number-control';
            input.min = String(min); input.max = String(max); input.step = String(step); input.required = true;
            input.dataset.setting = key;
            row.appendChild(input); section.appendChild(row);
            return input;
        }
        host._connectionIdle = numberRow('Idle timeout (seconds)', 'idle_timeout', 30, 3600, 30);
        host._connectionMax = numberRow('Maximum pooled connections', 'max_sessions', 1, 16, 1);
        host._connectionSave = button(label('save'), function () {
            var idle = Number(host._connectionIdle.value), max = Number(host._connectionMax.value);
            if (!Number.isInteger(idle) || idle < 30 || idle > 3600 || !Number.isInteger(max) || max < 1 || max > 16) {
                HF.set_error_status(HF.tr('Enter valid SSH connection limits'));
                return;
            }
            host._connectionSave.disabled = true;
            request('connection_settings_save', {
                idle_timeout: String(idle), max_sessions: String(max)
            }, true).then(function (data) {
                renderConnectionSettings(host, data);
                HF.set_status(HF.labels.settings_saved, 'success');
            }).catch(function (error) {
                HF.set_error_status(error.message || HF.labels.request_failed);
            }).finally(function () { host._connectionSave.disabled = false; });
        }, true);
        host._connectionSave.type = 'button';
    }
    function renderConnectionSettings(host, settings) {
        if (!settings || !host._connectionSettings) return;
        host._connectionIdle.value = String(settings.idle_timeout || 300);
        host._connectionMax.value = String(settings.max_sessions || 4);
    }

    function buildSettings(host) {
        if (host._inputs) return;
        host.className = 'fm-settings-panel-main fm-remote-settings';
        var connectionHost = document.getElementById('fm_remote_connection_settings_host');
        host._devices = HF.Util.createElement('div', 'fm-remote-devices');
        buildConnectionSettings(host);
        connectionHost.appendChild(host._connectionSettings);
        host._editButtons = new Map(); host._deviceBlocks = new Map();
        host._addBlock = HF.Util.createElement('div', 'fm-remote-add');
        var addActions = HF.Util.createElement('div', 'fm-settings-page-actions');
        host._add = button(label('add'), function() { editDevice(''); });
        host._add.setAttribute('aria-controls', 'fm_remote_device_form');
        addActions.appendChild(host._add); host._addBlock.appendChild(addActions);
        var form = host._form = HF.Util.createElement('form', 'fm-remote-editor');
        form.id = 'fm_remote_device_form'; form.hidden = true; host._inputs = Object.create(null);
        ['name', 'host', 'port', 'username', 'password'].forEach(function(key) {
            var row = HF.Util.createElement('div', 'fm-settings-row');
            var text = HF.Util.createElement('label', 'fm-settings-label', label(key));
            var input = HF.Util.createElement('input', 'fm-settings-control ' + (key === 'port' ? 'fm-settings-number-control' : 'fm-settings-text-control'));
            input.id = 'fm_remote_' + key; text.htmlFor = input.id;
            input.type = key === 'port' ? 'number' : key === 'password' ? 'password' : 'text';
            input.autocomplete = 'off'; input.spellcheck = false;
            input.required = true;
            input.placeholder = inputPlaceholder(key);
            input.addEventListener('input', function() { input.setCustomValidity(''); });
            input.maxLength = key === 'password' ? 1024 : key === 'name' ? 128 : key === 'username' ? 64 : 253;
            if (key === 'port') { input.min = '1'; input.max = '65535'; }
            host._inputs[key] = input;
            row.appendChild(text);
            row.appendChild(input);
            form.appendChild(row);
        });
        var actions = HF.Util.createElement('div', 'fm-settings-page-actions');
        var cancel = button(label('cancel'), function() { if (!host._saving) closeDeviceEditor(host); });
        var save = button(label('save'), function() {}, true); save.type = 'submit';
        actions.appendChild(cancel); actions.appendChild(save); form.appendChild(actions);
        host._save = save; host._cancel = cancel;
        host._message = HF.Util.createElement('div', 'fm-remote-status'); host._message.setAttribute('role', 'status');
        host._addBlock.appendChild(form); host._addBlock.appendChild(host._message);
        host.appendChild(host._addBlock);
        host.appendChild(host._devices);
        host._connectionActions = HF.Util.createElement('div', 'fm-settings-page-actions');
        host._connectionActions.appendChild(host._connectionSave);
        connectionHost.appendChild(host._connectionActions);
        updateDeviceEditor(host);
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            if (form.hidden || host._loading || host._saving) return;
            Object.keys(host._inputs).forEach(function(key) {
                var input = host._inputs[key];
                input.setCustomValidity(input.value.trim() || !input.required ? '' : label('required'));
            });
            if (!form.reportValidity()) return;
            var editSequence = host._editorSequence || 0;
            var values = { id: host._deviceId || '' };
            var previous = devices.get(values.id);
            Object.keys(host._inputs).forEach(function(key) { values[key] = host._inputs[key].value; });
            host._saving = true; updateDeviceEditor(host);
            request('save', values).then(function(data) {
                if (editSequence === (host._editorSequence || 0)) closeDeviceEditor(host);
                deviceChanged(data.id, !!previous && (previous.host !== values.host.trim() || previous.port !== Number(values.port) || previous.username !== values.username));
                HF.set_status(HF.labels.settings_saved, 'success');
                HF.render_remote_settings();
            }).catch(function(error) { host._message.textContent = error.message; }).finally(function() { host._saving = false; updateDeviceEditor(host); });
        });
    }
    HF.render_remote_settings = function() {
        var host = document.getElementById('fm_remote_settings');
        if (!host) return;
        buildSettings(host);
        var sequence = ++settingsSequence;
        updateDeviceEditor(host);
        loadDevices().then(function(data) {
            if (sequence !== settingsSequence) return;
            renderConnectionSettings(host, data.connection);
            host._addBlock.appendChild(host._form);
            HF.clear_node(host._devices); host._editButtons.clear(); host._deviceBlocks.clear();
            data.devices.forEach(function(d) {
                var row = HF.Util.createElement('div', 'fm-settings-row');
                var copy = HF.Util.createElement('div', 'fm-settings-copy');
                copy.appendChild(HF.Util.createElement('div', 'fm-settings-label', d.name));
                row.appendChild(copy);
                var actions = HF.Util.createElement('div', 'fm-nginx-actions');
                var edit = button(label('edit'), function() { editDevice(d.id); });
                edit.setAttribute('aria-controls', 'fm_remote_device_form');
                host._editButtons.set(d.id, edit);
                actions.appendChild(edit);
                actions.appendChild(button(label('remove'), function() {
                    HF.confirm_window({ title: label('remove'), message: label('delete') + '\n' + d.name }).then(function(yes) {
                        if (!yes) return;
                        request('delete', { id: d.id }).then(function() {
                            deviceChanged(d.id, true);
                            if (host._deviceId === d.id) closeDeviceEditor(host);
                            HF.render_remote_settings();
                        }).catch(function(error) { host._message.textContent = error.message; });
                    });
                }));
                row.appendChild(actions);
                var block = HF.Util.createElement('div', 'fm-remote-device');
                block.dataset.deviceId = d.id; host._deviceBlocks.set(d.id, block);
                block.appendChild(row);
                if (!host._form.hidden && host._deviceId === d.id) block.appendChild(host._form);
                host._devices.appendChild(block);
            });
            if (host._deviceId && !host._deviceBlocks.has(host._deviceId)) closeDeviceEditor(host);
            updateDeviceEditor(host);
            if (host._openAdd) {
                host._openAdd = false;
                if (document.getElementById('fm_settings_panel_remote').classList.contains('active')) editDevice('');
            }
        }).catch(function(error) {
            if (sequence !== settingsSequence) return;
            host._openAdd = false;
            updateDeviceEditor(host);
            host._message.textContent = error.message;
        });
    };
    var installView = HF.update_package_install_view;
    HF.update_package_install_view = function(data) {
        installView(data);
        if (data && data.done && remoteSettingsActive()) HF.render_remote_settings();
    };
    HF.run_remote_paste = function(targetPath, accessChecked) {
        var clipboard = HF.state.clipboard;
        if (!clipboard || !clipboard.items.length) return HF.set_warning_status(HF.labels.clipboard_empty);
        if (!accessChecked && HF.is_system_folder(targetPath)) {
            HF.with_system_access(targetPath, activeDevice(), function() { HF.run_remote_paste(targetPath, true); });
            return;
        }
        if (!HF.can_paste_to_path(targetPath)) return HF.set_warning_status(HF.get_write_block_reason(targetPath));
        HF.run_remote_transfer(clipboard.mode === 'cut' ? 'move' : 'copy', clipboard.items, { source_device: clipboard.device_id || '', source_revision: clipboard.device_revision || '', target_device: activeDevice(), target_revision: HF.state.current && HF.state.current.device_revision || '', target_dir: targetPath }, clipboard);
    };
    HF.run_remote_transfer = function(action, items, context, clipboard, accessChecked) {
        HF.hide_context_menus();
        var targetPath = context.target_dir;
        context = Object.assign({}, context, { operation: action });
        var internal = !!context.source_device && context.source_device === context.target_device;
        items = items.map(function(item) { return Object.assign({}, item); });
        if (!items.length || !targetPath) return;
        if (!accessChecked) {
            var accessPath = HF.transfer_system_access_path(items, targetPath);
            if (accessPath) {
                HF.with_system_access(accessPath, context.target_device || activeDevice(), function() {
                    HF.run_remote_transfer(action, items, context, clipboard, true);
                });
                return;
            }
        }
        if (HF.state.selection_mode) HF.exit_selection_mode();
        var adapter = {
            check: function(data, okay, failed) {
                requiredRequest('check', Object.assign({}, context, data)).then(okay).catch(function(error) { (failed || HF.set_error_status)(error.message); });
            },
            execute: function(action, selected, path, conflict, names, preserve, skipped, excluded) {
                if (!selected.length) return;
                var params = Object.assign({}, context, {
                    sources: JSON.stringify(selected.map(function(item) { return item.path; })),
                    conflict_action: conflict || 'error', preserve_permissions: preserve === false ? '0' : '1',
                    exclude_paths: JSON.stringify(excluded || [])
                });
                if (names) params.rename_map = JSON.stringify(names);
                var task = { started: Date.now(), clipboard: clipboard, id: 'pending-' + (++taskSequence), context: context, excluded: (excluded || []).slice(), activity: selected.map(function(item) { return item.path || item.name || ''; }).filter(Boolean), description: nameOf(context.source_device) + ' → ' + nameOf(context.target_device), data: { done: false, preparing: true }, lastBytes: 0, lastTime: Date.now(), reportStatus: internal, recoveryAttempts: new Set() };
                task.restart = function() {
                    if (!transferOwnersCurrent(task)) {
                        task.data = { done: true, success: false, message: label('stale_device') }; updateTask(task); finishTask(task); return;
                    }
                    task.data = { done: false, preparing: true }; updateTask(task);
                    requiredRequest('start', params).then(function(data) {
                        if (!data.task_id) { task.data = data; updateTask(task); finishTask(task); return; }
                        task.id = data.task_id; task.data = data; task.lastBytes = 0; task.lastTime = Date.now();
                        updateTask(task); if (!finishTask(task)) pollTask(task);
                    }).catch(function(error) {
                        task.data = { done: true, success: false, uncertain: !!error.uncertain, failure_data: error.data, message: action === 'move' && error.uncertain ? label('move_unconfirmed') + '\n' + error.message : error.message }; updateTask(task);
                        if (task.reportStatus) HF.set_error_status(transferMessage(task.data));
                    });
                };
                // Same-device transfers can be long too. Give them the same
                // progress/cancellation controls as cross-device transfers.
                showTask(task);
                task.restart();
            }
        };
        adapter.check({ sources: JSON.stringify(items.map(function(item) { return item.path; })) }, function(data) {
            if (data.conflicts && data.conflicts.length) HF.showPasteConflictDialog(data.conflicts, action, items, targetPath, adapter);
            else adapter.execute(action, items, targetPath);
        });
    };
    function showTask(task) {
    if (!task.panel) {
        var panelSource = HF.upload_panel_node || document.getElementById('fm_upload_panel');
        if (!panelSource) {
            panelSource = document.createElement('div');
            panelSource.className = 'fm-upload-panel';
            panelSource.innerHTML = '<div class="fm-upload-heading"><div class="fm-upload-title">-</div><div class="fm-upload-percent">0%</div></div><div class="fm-upload-progress"><span></span></div><div class="fm-upload-detail">-</div><div class="fm-upload-bytes">-</div><div class="fm-upload-speed">-</div>';
        }
        var panel = panelSource.cloneNode(true);
        panel.removeAttribute('id'); panel.querySelectorAll('[id]').forEach(function(node) { node.removeAttribute('id'); });
        panel.className = 'fm-upload-panel show fm-remote-transfer';
        panel.querySelector('.fm-upload-percent').style.display = 'none';
        var controls = panel.querySelector('.fm-upload-controls');
        if (!controls) {
            controls = HF.Util.createElement('div', 'fm-upload-controls');
            panel.querySelector('.fm-upload-heading').appendChild(controls);
        }
        // A clone may inherit visible upload controls, but not their handlers.
        controls.querySelectorAll('button').forEach(function(node) { node.hidden = true; });
        var autoLabel = panel.querySelector('.fm-upload-autoclose span');
        if (autoLabel) autoLabel.textContent = HF.tr('Close when finished');
        task.panel = panel;
    }
        if (!task.record || task.record.closed) task.record = HF.window_manager.create({
            title: label('transfer'), icon: 'upload', className: 'fm-upload-window fm-remote-window', content: task.panel,
            width: 480, height: 250, minWidth: 320, minHeight: 180, persistSize: false,
            onClose: function() {
                if (!task.data.done) {
                    task.cancelIntent = true;
                    requestTaskCancellation(task);
                }
            }
        });
        else HF.window_manager.show(task.record);
        startTaskActivity(task);
        updateTask(task);
    }
    function stopTaskActivity(task) {
        if (task.activityTimer) window.clearInterval(task.activityTimer);
        task.activityTimer = null;
        var detail = task.panel && task.panel.querySelector('.fm-upload-detail');
        if (detail && (task.data && task.data.done || !(task.data && task.data.current_file))) detail.classList.remove('fm-upload-activity');
    }
    function startTaskActivity(task) {
        stopTaskActivity(task);
        var paths = task.activity || [];
        if (!paths.length) return;
        var step = 0;
        function tick() {
            if (!task.panel || task.data && task.data.done) { stopTaskActivity(task); return; }
            if (task.data && task.data.current_file) return;
            var detail = task.panel.querySelector('.fm-upload-detail');
            if (!detail) return;
            detail.classList.add('fm-upload-activity');
            var path = paths[step % paths.length];
            step++;
            detail.textContent = task.description + ' · ' + task.context.target_dir + (path ? ' · ' + path : '');
        }
        tick();
        task.activityTimer = window.setInterval(tick, 450);
    }
    function requestTaskCancellation(task) {
        if (task.data.done || task.data.cancelable !== true || task.cancelBusy || task.cancelConfirmed || task.cancelDenied) return;
        // Intent is sticky even if the HTTP response is lost: an automatic
        // preflight recovery must not restart a task the user tried to stop.
        task.cancelIntent = true;
        task.cancelBusy = true;
        task.cancelNote = label('cancel_sending');
        updateTask(task);
        function unconfirmed(xhr) {
            task.cancelBusy = false;
            // A status poll can confirm the request (or finish the task)
            // before this HTTP response arrives. An older failed response
            // must not overwrite that newer, authoritative observation.
            if (task.cancelConfirmed || task.data.done) return updateTask(task);
            if (xhr && xhr.status === 409) {
                task.cancelDenied = true;
                task.cancelNote = label('cancel_too_late');
            } else task.cancelNote = label('cancel_unconfirmed');
            updateTask(task);
        }
        HF.Util.ajax({
            url: HF.api.task_cancel, type: 'POST', dataType: 'json', timeout: 15000,
            data: { task_id: task.id, sessionid: HF.sessionid || (window.HarborIO && HarborIO.getSessionID()) || '' },
            success: function(res) {
                if (!res || res.code !== 0 || !res.data || res.data.cancel_requested !== true) return unconfirmed();
                task.cancelBusy = false;
                task.cancelConfirmed = true;
                task.cancelNote = label('cancel_requested');
                updateTask(task);
            },
            error: unconfirmed
        });
    }
    function transferMessage(data) {
        var stage = data.failure_data && data.failure_data.staging_path || data.staging_path;
        var message = data.state === 'cancelled' ? label(stage ? 'cancelled_staging' : 'cancelled_safe') :
            HF.tr(data.message || data.error || HF.labels.operation_failed);
        if (stage) message += '\n' + HF.format_label(HF.tr('Staging path: %s'), stage);
        return message;
    }
    function updateTask(task) {
        var data = task.data, panel = task.panel;
        if (data.done && data.success && task.context.operation === 'move' && data.operation !== 'move') { data.success = false; data.message = label('move_unconfirmed'); }
        if (!panel) return;
        panel.classList.toggle('fm-remote-running', !data.done);
        panel.classList.toggle('success', !!data.done && !!data.success);
        panel.classList.toggle('error', !!data.done && !data.success);
        if (task.cancelIntent && !data.done) requestTaskCancellation(task);
        var elapsedSec = task.elapsedFinal != null ? task.elapsedFinal : Math.max(Number(data.elapsed) || 0, (Date.now() - task.started) / 1000);
        if (data.done && task.elapsedFinal == null) task.elapsedFinal = elapsedSec;
        panel.querySelector('.fm-upload-title').textContent = data.uncertain ? HF.labels.task_status_unknown : task.waiting ? label('waiting') : data.done ? (data.success ? task.context.operation === 'move' ? HF.labels.move_complete : HF.labels.copy_complete : data.state === 'cancelled' ? label('cancelled') : label('failed')) : data.preparing ? label('scanning') : task.cancelNote || (['hashing', 'verifying', 'deleting', 'scanning', 'publishing'].indexOf(data.phase) >= 0 ? label(data.phase) : label('transfer'));
        panel.querySelector('.fm-upload-progress span').style.width = data.done ? (data.success ? '100%' : '0%') : (data.percent > 0 ? data.percent + '%' : '30%');
        var detailNode = panel.querySelector('.fm-upload-detail');
        var current = data.current_file || '';
        detailNode.textContent = task.description + ' · ' + task.context.target_dir + (current ? ' · ' + current : '');
        if (!data.done && (current || task.activity && task.activity.length)) detailNode.classList.add('fm-upload-activity');
        else detailNode.classList.remove('fm-upload-activity');
        if (data.done) stopTaskActivity(task);
        else if (!current && task.activity && task.activity.length && !task.activityTimer) startTaskActivity(task);
        var elapsedNode = panel.querySelector('.fm-upload-elapsed');
        if (elapsedNode) {
            elapsedNode.textContent = label('elapsed') + ': ' + HF.format_elapsed(elapsedSec);
            panel.querySelector('.fm-upload-bytes').textContent = label('transferred') + ': ' + HF.format_size(data.bytes || 0);
        } else {
            panel.querySelector('.fm-upload-bytes').textContent = label('transferred') + ': ' + HF.format_size(data.bytes || 0) + ' · ' + label('elapsed') + ': ' + HF.format_elapsed(elapsedSec);
        }
        panel.querySelector('.fm-upload-speed').textContent = data.done && !data.success ? transferMessage(data) : HF.format_speed(task.speed || 0);
        if (data.done && data.source_results) panel.querySelector('.fm-upload-speed').textContent += '\n' + data.source_results.map(function(result) { return result.path + ' · ' + label('source_' + result.state) + (result.deleted_count ? ' (' + result.deleted_count + ')' : '') + (result.state !== 'deleted' && result.deleted_paths && result.deleted_paths.length ? '\n' + result.deleted_paths.map(function(path) { return label('source_deleted') + ': ' + path; }).join('\n') + (result.more_deleted_paths ? '\n…' : '') : ''); }).join('\n');
    }
    function finishTask(task) {
        var data = task.data;
        if (!data.done || data.uncertain || task.waiting) return false;
        if (task.completed) return true;
        task.completed = true;
        if (task.clipboard && task.clipboard === HF.state.clipboard && task.context.operation === 'move') {
            var removed = new Set();
            if (data.source_results) {
                data.source_results.filter(function(result) { return result.state === 'deleted'; }).forEach(function(result) { removed.add(result.path); });
            } else if (data.success && data.items) {
                data.items.forEach(function(entry) {
                    if (!entry || !entry.from) return;
                    var prefix = entry.from.replace(/\/$/, '') + '/';
                    // A verified move intentionally leaves excluded descendants
                    // in the source tree; keep that parent on the clipboard.
                    if (!(task.excluded || []).some(function(skip) { return skip === entry.from || skip.indexOf(prefix) === 0; })) removed.add(entry.from);
                });
            }
            if (removed.size) {
                task.clipboard.items = task.clipboard.items.filter(function(item) { return !removed.has(item.path); });
                if (!task.clipboard.items.length) HF.state.clipboard = null;
            }
        }
        if (task.reportStatus) {
            if (data.success) HF.set_status(task.context.operation === 'move' ? HF.labels.move_complete : HF.labels.copy_complete, 'success');
            else HF.set_error_status(transferMessage(data));
        }
        if (!task.reportStatus && (!task.record || task.record.closed)) {
            if (data.success) HF.notify(HF.tr('Background transfer complete'), 'success');
            else HF.notify(transferMessage(data), 'error');
        }
        var target = devices.get(task.context.target_device);
        if (target && target.revision === task.context.target_revision) {
            capacities.delete(target.id);
            if (activeDevice() !== target.id || !HF.state.current || HF.state.current.kind !== 'directory') ensureCapacity(target);
        }
        if ((activeDevice() === task.context.target_device || task.context.operation === 'move' && activeDevice() === task.context.source_device) && HF.state.current && HF.state.current.kind === 'directory') HF.refresh_current();
        if (data.success && task.record && !task.record.closed) {
            var auto = task.panel && task.panel.querySelector('.fm-upload-autoclose-input');
            if (auto && auto.checked) {
                window.setTimeout(function() {
                    if (task.record && !task.record.closed) HF.window_manager.close(task.record);
                }, 700);
            }
        }
        return true;
    }
    function transferUnknown(task, message) {
        task.pollStopped = true;
        task.waiting = false;
        var cancellation = task.cancelIntent || task.data.cancel_requested === true ||
            task.data.failure_data && task.data.failure_data.cancel_requested === true;
        task.data = Object.assign({}, task.data, { done: true, success: false, state: 'unknown', uncertain: true,
            message: (cancellation ? label('cancel_unconfirmed') : HF.tr(message || HF.labels.task_status_unknown)) + '\n' + label('outcome_unknown') });
        updateTask(task);
        if (task.reportStatus) HF.set_error_status(transferMessage(task.data));
        else if (!task.record || task.record.closed) HF.notify(transferMessage(task.data), 'error');
        // Never mark the clipboard complete or replay an operation whose
        // status was lost; the background worker may still be running.
    }
    function transferOwnersCurrent(task) {
        return HF.remote_owner_current({ device_id: task.context.source_device || '', device_revision: task.context.source_revision || '' }) &&
            HF.remote_owner_current({ device_id: task.context.target_device || '', device_revision: task.context.target_revision || '' });
    }
    function recoverTransferPreflight(task, data) {
        var info = data.failure_data || {};
        if (!data.done || data.success || data.state !== 'failed' || info.preflight_safe !== true ||
            task.cancelIntent || data.cancel_requested === true || info.cancel_requested === true ||
            info.partial === true || info.outcome_unknown === true || !transferOwnersCurrent(task)) return false;
        var owners = [
            { device_id: task.context.source_device || '', device_revision: task.context.source_revision || '' },
            { device_id: task.context.target_device || '', device_revision: task.context.target_revision || '' }
        ];
        if (typeof info.device_id !== 'string') info = Object.assign({}, info, { device_id: '' });
        var owner = owners.find(function(value) { return value.device_id === info.device_id &&
            (!info.device_id || info.device_revision === undefined || value.device_revision === info.device_revision); });
        if (!owner) return false;
        function giveUp() { updateTask(task); finishTask(task); }
        function restart() {
            if (task.cancelIntent || task.data.cancel_requested === true) return giveUp();
            if (transferOwnersCurrent(task)) task.restart(); else { task.data.message = label('stale_device'); giveUp(); }
        }
        if (info.missing_tool && info.dependency_preflight === true && /^[A-Za-z0-9][A-Za-z0-9._+\-]{0,127}$/.test(info.missing_tool)) {
            var toolKey = JSON.stringify(['tool', owner.device_id, owner.device_revision, info.missing_tool]);
            if (task.recoveryAttempts.has(toolKey) || task.recoveryAttempts.size >= 16) return false;
            task.recoveryAttempts.add(toolKey); task.pollStopped = true;
            HF.ensure_dependency(info.missing_tool, owner, { evidence: info }).then(function(ready) {
                if (ready) restart(); else giveUp();
            }, giveUp);
            return true;
        }
        if (info.system_access_required === true && typeof info.path === 'string' && info.path.charAt(0) === '/') {
            var accessKey = JSON.stringify(['access', owner.device_id, info.path]);
            if (task.recoveryAttempts.has(accessKey) || task.recoveryAttempts.size >= 16) return false;
            var handled = HF.retry_system_access(null, null, { message: data.message, data: info }, restart, giveUp);
            if (handled) { task.recoveryAttempts.add(accessKey); task.pollStopped = true; return true; }
        }
        return false;
    }
    function pollTask(task) {
        task.pollStopped = false;
        task.poller = HF.poll_job({
            active: function() { return !task.pollStopped; },
            continuePolling: function() { return !task.pollStopped; },
            successDelay: function() { return Date.now() - task.started < 5000 ? 250 : 1000; },
            request: function(okay, failed) { request('status', { task_id: task.id }, true).then(okay, failed); },
            onData: function(data) {
                var now = Date.now();
                task.speed = Math.max(0, (Number(data.bytes || 0) - task.lastBytes) * 1000 / Math.max(1, now - task.lastTime));
                task.lastBytes = Number(data.bytes || 0); task.lastTime = now;
                task.data = data; task.waiting = false;
                if (data.cancel_requested === true) {
                    task.cancelConfirmed = true;
                    task.cancelNote = label('cancel_requested');
                }
                if (data.done && (data.state === 'unknown' || data.state === 'gone')) return transferUnknown(task, data.message);
                if (recoverTransferPreflight(task, data)) { updateTask(task); return; }
                updateTask(task);
                if (finishTask(task)) task.pollStopped = true;
            },
            onError: function(error, count, exhausted) {
                if (exhausted) return transferUnknown(task, HF.labels.task_status_unknown);
                task.waiting = true; updateTask(task);
            }
        });
    }
    HF.configure_target_devices = function(options) {
        var select = document.getElementById('fm_target_device');
        if (!select) {
            select = HF.Util.createElement('select', 'fm-settings-control fm-target-device');
            select.id = 'fm_target_device'; select.setAttribute('aria-label', label('target_device'));
            var address = document.getElementById('fm_target_path');
            address.parentNode.insertBefore(select, address);
            select.addEventListener('change', function() {
                var picker = HF.state.target_picker;
                if (!picker || !picker.allow_devices) return;
                sizeDevice();
                picker.device_id = select.value; picker.device_revision = '';
                HF.state.target_path = null; HF.state.target_parent = null; HF.state.target_has_operation_space = false;
                HF.clear_node(document.getElementById('fm_target_list'));
                var control = address._fmPathAddress; if (control) control.exit();
                HF.render_target_address();
                HF.load_target_directory(picker.device_paths[picker.device_id] || (picker.device_id ? lastPaths[picker.device_id] : HF.state.navigation.home_dir) || '/', true);
            });
        }
        function sizeDevice() {
            var option = select.options[select.selectedIndex];
            if (!option) return;
            select.title = option.title;
            HF.size_select_to_content(select);
        }
        select.hidden = !options.allow_devices;
        if (!options.allow_devices) return;
        options.device_id = options.device_id || '';
        options.device_paths = options.device_paths || Object.create(null);
        HF.clear_node(select);
        function option(id, name, disabled) {
            var chars = Array.from(name || '');
            var node = HF.Util.createElement('option', '', chars.length > 18 ? chars.slice(0, 18).join('') + '…' : name); node.title = name; node.value = id; node.disabled = !!disabled; select.appendChild(node);
        }
        option('', HF.labels.this_pc);
        devices.forEach(function(d) { option(d.id, d.name); });
        if (options.device_id && !devices.has(options.device_id)) option(options.device_id, options.device_id + ' · ' + label('unavailable'), true);
        select.value = options.device_id;
        sizeDevice();
        options.load = function(path, okay, failed, active) {
            if (!options.device_id) { HF.request_json(HF.api.list, { path: path }, okay, failed); return; }
            var id = options.device_id;
            HF.read_remote_directory(id, path, active).then(function(data) {
                if (active() && id === options.device_id && devices.has(id) && data.device_revision === devices.get(id).revision) okay(data);
            }).catch(function(error) { if (active()) failed(error.message, !!error.stopFallback); });
        };
        if (!devicesLoaded && !devicesLoading) loadDevices().catch(function(error) { HF.target_address_error(error.message); });
    };
    HF.open_transfer_dialog = function(action, items) {
        items = HF.normalize_item_list(Array.isArray(items) ? items : [items]);
        var current = HF.state.current;
        if (!items.length || !current || current.kind !== 'directory') return;
        var source = current.device_id || '', revision = current.device_revision || '';
        HF.open_directory_picker({
            allow_devices: true, device_id: source,
            title: action === 'copy' ? HF.labels.copy_to : HF.labels.move_to,
            confirm: action === 'copy' ? HF.labels.copy_to : HF.labels.move_to,
            source: nameOf(source) + ' · ' + (items.length > 1 ? HF.format_label(HF.labels.selected_items, items.length) : items[0].path),
            path: current.path,
            accept: function(path, id, targetRevision) {
                if (!source && !id) HF.run_batch_transfer(action, items, path);
                else HF.run_remote_transfer(action, items, { source_device: source, source_revision: revision, target_device: id, target_revision: targetRevision, target_dir: path });
            }
        });
    };
    if (HF.FileOperations) HF.FileOperations.open_transfer_dialog = HF.open_transfer_dialog;
    var localTerminal = HF.open_terminal;
    HF.open_terminal = function(item) {
        var owner = HF.file_context(item && item.device_id !== undefined ? item : HF.state.current);
        if (!owner.device_id) return localTerminal(item);
        owner.path = HF.resolve_terminal_target(item).path;
        HF.hide_context_menus(); HF.hide_details();
        var d = devices.get(owner.device_id);
        if (!d || d.revision !== owner.device_revision) return HF.set_error_status(label('stale_device'));
        return HF.create_terminal_window({ owner: owner, host: d.host, title: d.name + ' · ' + HF.labels.terminal });
    };
    if (HF.SystemWindows) HF.SystemWindows.open_terminal = HF.open_terminal;
    var preparingFiles = new Map(), preparedFiles = new Map();
    function invalidateFiles(id) {
        preparedFiles.delete(id);
    }
    HF.ensure_remote_files = function(owner) {
        if (!owner || !owner.device_id) return Promise.resolve();
        var d = devices.get(owner.device_id), revision = owner.device_revision;
        if (!d || typeof revision !== 'string' || revision !== d.revision) return Promise.reject(new Error(label('stale_device')));
        var cached = preparedFiles.get(d.id);
        if (cached && cached.revision === revision && Date.now() - cached.time < 60000) return Promise.resolve(cached.data);
        var key = d.id + ':' + revision;
        if (preparingFiles.has(key)) return preparingFiles.get(key);
        var pending = requiredRequest('agent_prepare', { device_id: d.id, device_revision: revision }).then(function(data) {
            if (!data.ready || data.device_revision !== revision || !devices.has(d.id) || devices.get(d.id).revision !== revision) throw new Error(label('stale_device'));
            preparedFiles.set(d.id, { revision: revision, time: Date.now(), data: data });
            return data;
        }).finally(function() { preparingFiles.delete(key); });
        preparingFiles.set(key, pending);
        return pending;
    };
    function fileRequest(owner, action, data, retried) {
        return HF.ensure_remote_files(owner).then(function() {
            var send = ['archive_status', 'thumbnail_generate_status', 'package_install_status'].indexOf(action) >= 0 ? request : requiredRequest;
            return send('rpc', Object.assign({}, owner, { rpc_action: action, rpc_data: JSON.stringify(data) }));
        }).then(function(res) {
            if (res && typeof res.code === 'number') {
                if (res.code !== 0) {
                    invalidateFiles(owner.device_id);
                    if (!retried && res.data && res.data.helper_missing && ['list', 'detect_type', 'read_text', 'archive_status', 'thumbnail_generate_status', 'package_install_status'].indexOf(action) >= 0) return fileRequest(owner, action, data, true);
                }
                return res;
            }
            return { code: 0, message: 'success', data: res || {} };
        }).catch(function(error) { invalidateFiles(owner.device_id); throw error; });
    }
    // Explicit adapter for file endpoints. The base HF.Util.ajax is not
    // replaced, so ordinary HTTP requests cannot be accidentally intercepted.
    HF.remote_ajax = function(owner, action, data, options) {
        owner = { device_id: owner.device_id, device_revision: owner.device_revision || '' };
        data = Object.assign({}, data || {});
        options = options || {};
        function deliver(res) {
            if (res && res.data && typeof res.data === 'object') {
                res.data.device_id = owner.device_id;
                res.data.device_revision = owner.device_revision;
                if (res.data.missing_tool && res.data.dependency_preflight === true && res.data.outcome_unknown !== true) res.data.remote_retry = function() { HF.remote_ajax(owner, action, data, options); };
                (res.data.items || []).forEach(function(item) { item.device_id = owner.device_id; item.device_revision = owner.device_revision; });
            }
            if (options.success) options.success(res);
        }
        return fileRequest(owner, action, data).then(deliver).catch(function(error) {
            deliver({ code: error.code || 1, message: error.message + (error.uncertain && String(options.type || 'GET').toUpperCase() === 'POST' ? '\n' + label('outcome_unknown') : ''), data: error.data });
        });
    };
    var originalOpenItem = HF.open_item;
    HF.open_item = function(item, force, accessChecked) {
        if (!item || !item.device_id) return originalOpenItem(item, force, accessChecked);
        HF.hide_details(); HF.hide_context_menus();
        if (item.type === 'directory') return HF.open_remote_path(item.device_id, item.path, true);
        if (force || accessChecked || item.preview === 'package' || HF.is_archive_item(item)) return originalOpenItem(item, force, accessChecked);
        HF.request_json(HF.file_endpoint('detect_type', item), { path: item.path }, function(data) {
            var detected_preview = data.preview && data.preview !== 'none' ? data.preview :
                (data.kind === 'text' ? 'text' : data.kind === 'image' ? 'image' : data.kind === 'pdf' ? 'pdf' : data.kind === 'video' ? 'video' : data.kind === 'audio' ? 'audio' : data.kind === 'document' ? 'document' : item.preview || 'none');
            item.preview = detected_preview;
            originalOpenItem(item, force, accessChecked);
        });
    };
    ['open_binary', 'open_text', 'open_image', 'open_pdf', 'open_video', 'open_properties', 'trigger_download', 'start_archive_extract'].forEach(function(key) {
        var original = HF[key];
        HF[key] = function(item) {
            if (!item || !item.device_id) return original.apply(HF, arguments);
            var args = Array.prototype.slice.call(arguments);
            HF.ensure_remote_files(item).then(function() {
                var record = original.apply(HF, args);
                if (key === 'open_properties') record = document.getElementById('fm_property_dialog')._fmWindow;
                if (record && record.title_node) {
                    var title_node = record.title_node, prefix = nameOf(item.device_id) + ' · ';
                    if (typeof title_node._fmBaseTitle !== 'string') title_node._fmBaseTitle = title_node.textContent;
                    title_node.textContent = prefix + title_node._fmBaseTitle;
                }
            }).catch(function(error) { HF.set_error_status(error.message); });
        };
        if (HF.DocumentWindows && HF.DocumentWindows[key] === original) HF.DocumentWindows[key] = HF[key];
        if (HF.SystemWindows && HF.SystemWindows[key] === original) HF.SystemWindows[key] = HF[key];
        if (HF.FileOperations && HF.FileOperations[key] === original) HF.FileOperations[key] = HF[key];
    });
    if (HF.FileOperations) HF.FileOperations.open_item = HF.open_item;
    var localArchiveProgress = HF.start_archive_progress;
    HF.start_archive_progress = function(data, on_conflict, retry, attempts) {
        if (!data || !data.device_id) return localArchiveProgress(data);
        return HF.remote_archive_job(data, on_conflict, retry, attempts);
    };
    var pathTitle = HF.path_title;
    HF.path_title = function(path) { return activeDevice() ? (path === '/' ? nameOf(activeDevice()) : String(path).split('/').pop()) : pathTitle(path); };
})(window.HarborFile);
