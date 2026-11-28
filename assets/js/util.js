
(function (HF) {
    HF.file_context = function(owner) {
        owner = owner || HF.state.current || {};
        return { device_id: owner.device_id || '', device_revision: owner.device_revision || '', path: owner.path || '/' };
    };
    HF.file_key = function(item) { return item.device_id ? JSON.stringify([item.device_id, item.device_revision, item.path]) : item.path; };
    HF.file_io = function(item) { return item && item.device_id ? HarborIO.forDevice(item) : HarborIO; };
    // A remote endpoint is a typed descriptor, never a fake URL intercepted
    // by the global AJAX function. Local endpoints remain ordinary URLs.
    HF.file_endpoint = function(name, owner) {
        if (!owner || !owner.device_id) return HF.api[name];
        return { remote_file: true, action: name,
            owner: { device_id: owner.device_id, device_revision: owner.device_revision || '' } };
    };
    HF.file_ajax = function(options) {
        var endpoint = options && options.url;
        if (endpoint && typeof endpoint === 'object' && endpoint.remote_file === true) {
            if (!HF.remote_ajax) throw new Error('Remote file support is not loaded');
            return HF.remote_ajax(endpoint.owner, endpoint.action, options.data || {}, options);
        }
        return HF.Util.ajax(options);
    };
    HF.close_file_dialog = function(id) {
        var dialog = document.getElementById(id);
        if (dialog && dialog._fmWindow) HF.window_manager.close(dialog._fmWindow);
        else if (dialog) dialog.style.display = 'none';
    };
    HF.size_select_to_content = function size_select_to_content(select) {
        var option = select.options[select.selectedIndex];
        if (!option) return;
        var style = getComputedStyle(select);
        var measure = select._fmMeasure || (select._fmMeasure = document.createElement('canvas').getContext('2d'));
        if (!measure) { select.style.width = 'auto'; return; }
        measure.font = style.font || style.fontSize + ' ' + style.fontFamily;
        select.style.width = Math.ceil(measure.measureText(option.textContent).width +
            (parseFloat(style.paddingLeft) || 0) + (parseFloat(style.paddingRight) || 0) +
            (parseFloat(style.borderLeftWidth) || 0) + (parseFloat(style.borderRightWidth) || 0)) + 'px';
    };
    HF.permBits = [8,7,6, 5,4,3, 2,1,0];
    HF.status_duration_fast = 1800;
    HF.status_duration_warning = 0;
    HF.status_duration_long = 0;
    HF.system_folder_paths = {
        '/bin': true,
        '/sbin': true,
        '/proc': true,
        '/dev': true,
        '/etc': true,
        '/usr': true,
        '/sys': true,
        '/lib64': true,
        '/overlay': true,
        '/rom': true,
        '/www/cgi-bin': true
    };
    HF.state = {
        navigation: { quick_access: [], folders: [], drives: [], bookmarks: [], bookmark_folders: [], fav_expanded: [] },
        notice_record: null,
        toast_host: null,
        context_menu_shown_at: 0,
        system_blocked_notified: false,
        system_access_scope: '',
        system_access_device: '',
        preferences: {
            view_mode: 1,
            theme: 'auto',
            glass_light_transparency: 20,
            glass_light_blur: 16,
            glass_dark_transparency: 28,
            glass_dark_blur: 20,
            full_width: 1,
            system_access_active: 0,
            show_hidden_files: 0,
            home_dir: '/tmp/root',
            enable_thumbnails: 0,
            editor_auto_indent: 0,
            editor_auto_wrap: 0,
            editor_prism: 1,
            restore_last_directory: 0,
            show_line_numbers: 0,
            last_directory: '',
            window_width: 820,
            window_height: 590,
            mobile_window_width: 360,
            mobile_window_height: 560,
            terminal_ping: 30,
            terminal_idle: 300,
            terminal_ring_kb: 256,
            terminal_replay: 1
        },
        current: null,
        current_directory_data: null,
        selected: null,
        selected_items: [],
        selected_order: [],
        selection_anchor: null,
        selection_box: null,
        selection_base: [],
        selection_dragging: false,
        selection_moved: false,
        selection_start_x: 0,
        selection_start_y: 0,
        marquee_scroll_x: 0,
        marquee_scroll_y: 0,
        marquee_last_x: 0,
        marquee_last_y: 0,
        item_hover_timer: null,
        item_hover_card: null,
        item_hover_event: null,
        sort_field: 'name',
        sort_order: 'asc',
        sort_path: '',
        suppress_next_click: false,
        context_item: null,
        history: [],
        history_index: -1,
        uploading: false,
        upload_paused: false,
        upload_cancelled: false,
        upload_resume_waiters: [],
        upload_cancel_action: null,
        pending_upload: null,
        drag_target: null,
        upload_target: null,
        clipboard: null,
        name_action: null,
        delete_item: null,
        delete_items: [],
        status_timer: null,
        install_poller: null,
        install_item: null,
        install_task: null,
        install_job: null,
        thumbnail_task: null,
        thumbnail_poller: null,
        archive_poller: null,
        archive_items: [],
        archive_task: null,
        detected_types: {},
        detect_waiters: {},
        last_directory_sent: '',
        last_directory_pending: '',
        last_directory_timer: null,
        last_directory_inflight: false,
        last_directory_flush_requested: false,
        last_directory_retry_count: 0,
        last_directory_initialized: false,
        drag_item: null,
        drag_items: [],
        uploaded_bytes: 0,
        upload_total: 0,
        upload_speed: 0,
        upload_last_loaded: 0,
        upload_last_tick: 0,
        upload_started_at: 0,
        address_editing: false,
        view_mode: 'medium',
        transfer_action: null,
        target_path: '/',
    };

    HF.retry_system_access = function retry_system_access(url, data, res, retry, onDeny) {
        var message = String(res && res.message || '').toLowerCase();
        // A denial discovered after a mutation is not permission to replay it.
        if (res && res.data && (res.data.partial === true || res.data.outcome_unknown === true || res.data.preflight_safe === false)) return false;
        if (!(res && res.data && res.data.system_access_required) && message.indexOf('system folder access') < 0 && message.indexOf('system folder operations') < 0) return false;
        var candidates = [];
        function addCandidate(value, device) {
            if (typeof value === 'string' && value && candidates.every(function(c) { return c.path !== value || c.device !== (device || ''); })) {
                candidates.push({ path: value, device: device || '' });
            }
        }
        if (res && res.data) addCandidate(res.data.path, res.data.device_id || '');
        if (data) {
            addCandidate(data.path, data.device_id || '');
            addCandidate(data.target_dir, data.target_device || '');
            addCandidate(data.destination, data.target_device || '');
            addCandidate(data.dest, data.target_device || '');
            addCandidate(data.source, data.source_device || '');
            if (data.sources || data.paths) {
                try {
                    var list = JSON.parse(data.sources || data.paths);
                    if (Array.isArray(list)) list.forEach(function(value) { addCandidate(value, data.source_device || ''); });
                } catch (e) {}
            }
        }
        if (!candidates.length) return false;
        var chosen = null;
        for (var ci = 0; ci < candidates.length; ci++) {
            if (HF.is_system_folder && HF.is_system_folder(candidates[ci].path)) {
                chosen = candidates[ci];
                break;
            }
        }
        if (!chosen) chosen = candidates[0];
        var path = chosen.path;
        var deviceId = chosen.device || '';
        if (!deviceId && url && typeof url === 'object' && url.remote_file) {
            deviceId = url.owner && url.owner.device_id || '';
        }
        var systemPath = !!(HF.is_system_folder && HF.is_system_folder(path));
        var forcedPath = !systemPath && (candidates.length === 1 || !!(res && res.data && res.data.path === path));
        if ((!systemPath && !forcedPath) || !HF.ensure_system_access) return false;
        HF.ensure_system_access(path, deviceId, forcedPath).then(function(allowed) {
            if (allowed) retry();
            else if (onDeny) onDeny();
        });
        return true;
    }

    HF.request_json = function request_json(url, data, on_ok, on_error, accessRetried) {
        function fail_hard(message, res) {
            if (!accessRetried && HF.retry_system_access(url, data, res, function() {
                HF.request_json(url, data, on_ok, on_error, true);
            }, function() {
                if (on_error) {
                    on_error(message, res);
                    return;
                }
                HF.set_error_status(message || HF.labels.request_failed);
            })) return;
            if (on_error) {
                on_error(message, res);
                return;
            }
            HF.set_error_status(message || HF.labels.request_failed);
        }
        HF.file_ajax({
            url: url,
            type: 'GET',
            data: data || {},
            dataType: 'json',
            success: function(res) {
                if (!res || res.code !== 0) {
                    fail_hard(res && res.message ? res.message : HF.labels.request_failed, res);
                    return;
                }
                on_ok(res.data || {});
            },
            error: function(xhr) {
                var res = HF.response_json(xhr);
                if (!accessRetried && HF.retry_system_access(url, data, res, function() {
                    HF.request_json(url, data, on_ok, on_error, true);
                }, function() {
                    var denyMessage = res && res.message || HF.labels.request_failed + ': HTTP ' + xhr.status;
                    if (on_error) on_error(denyMessage, res);
                    else HF.set_error_status(denyMessage);
                })) return;
                fail_hard(res && res.message || HF.labels.request_failed + ': HTTP ' + xhr.status, res);
            }
        });
    }

    HF.status_timeout = function status_timeout(type, duration) {
        if (typeof duration === 'number' && duration >= 0) {
            return duration;
        }
        if (type === 'warning') {
            return HF.status_duration_warning;
        }
        if (type === 'error') {
            return HF.status_duration_long;
        }
        return HF.status_duration_fast;
    }

    
    function toast_region() {
        if (HF.state.toast_host && document.body.contains(HF.state.toast_host)) return HF.state.toast_host;
        var host = HF.Util.createElement('div', 'fm-toast-region');
        host.id = 'fm-toast-region';
        host.setAttribute('aria-live', 'polite');
        host.setAttribute('aria-relevant', 'additions text');
        document.body.appendChild(host);
        HF.state.toast_host = host;
        return host;
    }

    function remove_toast(toast, immediate) {
        if (!toast || !toast.parentNode) return;
        if (toast._notifyTimer) clearTimeout(toast._notifyTimer);
        toast._notifyTimer = null;
        if (immediate) {
            toast.parentNode.removeChild(toast);
            return;
        }
        toast.classList.add('is-closing');
        setTimeout(function() {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 180);
    }

    function show_toast(message, type, auto_close) {
        var host = toast_region();
        var text = String(message || '');
        var existing = Array.prototype.find.call(host.children, function(item) {
            return item.dataset.message === text && item.dataset.type === type;
        });
        if (existing) {
            if (existing._notifyTimer) clearTimeout(existing._notifyTimer);
            existing.classList.remove('is-closing');
            if (auto_close > 0) existing._notifyTimer = setTimeout(function() { remove_toast(existing, false); }, auto_close);
            return existing;
        }
        var toast = HF.Util.createElement('div', 'fm-toast fm-toast-' + type);
        toast.dataset.message = text;
        toast.dataset.type = type;
        toast.setAttribute('role', 'status');
        var icon = HF.Util.createElement('span', 'fm-toast-icon', type === 'success' ? '✓' : 'i');
        icon.setAttribute('aria-hidden', 'true');
        var content = HF.Util.createElement('div', 'fm-toast-content', text);
        var close = HF.Util.createElement('button', 'fm-toast-close', '×');
        close.type = 'button';
        close.setAttribute('aria-label', HF.tr('Close'));
        close.addEventListener('click', function() { remove_toast(toast, false); });
        toast.appendChild(icon);
        toast.appendChild(content);
        toast.appendChild(close);
        host.insertBefore(toast, host.firstChild);
        while (host.children.length > 4) remove_toast(host.lastElementChild, true);
        if (auto_close > 0) toast._notifyTimer = setTimeout(function() { remove_toast(toast, false); }, auto_close);
        return toast;
    }

    function append_window_notice(record, message, type) {
        var text = String(message || '');
        var entries = record.notice_entries || (record.notice_entries = []);
        if (entries.some(function(entry) { return entry.message === text && entry.type === type; })) return;
        entries.push({ message: text, type: type });
        var body = record.element.querySelector('.fm-notify-body');
        if (!body) return;
        var entry = HF.Util.createElement('div', 'fm-notify-message fm-notify-entry fm-notify-entry-' + type, text);
        body.appendChild(entry);
        body.scrollTop = body.scrollHeight;
        if (type === 'error') {
            record.element.classList.remove('fm-notify-warning');
            record.element.classList.add('fm-notify-error');
            if (record.title_node) record.title_node.textContent = HF.tr('Error');
            record.element.setAttribute('aria-label', HF.tr('Error'));
        }
    }

    HF.notify = function notify(message, type, auto_close) {
        if (!message) return null;
        type = type || 'notice';
        if (['error', 'warning', 'success', 'notice'].indexOf(type) < 0) type = 'notice';
        if (type !== 'error' && type !== 'warning') {
            return show_toast(message, type, typeof auto_close === 'number' ? auto_close : HF.status_timeout(type));
        }
        if (!HF.window_manager) return null;
        var existing = HF.state.notice_record;
        if (existing && !existing.closed) {
            append_window_notice(existing, message, type);
            HF.window_manager.focus(existing);
            return existing;
        }
        var body = HF.Util.createElement('div', 'fm-notify-body');
        var titles = { error: 'Error', warning: 'Warning' };
        var record = HF.window_manager.create({
            title: HF.tr(titles[type]),
            icon: 'file',
            className: 'fm-notify-window fm-notify-' + type,
            content: body,
            width: 460,
            height: 168,
            minWidth: 260,
            minHeight: 110,
            persistSize: false,
            onClose: function() {
                if (HF.state.notice_record === record) HF.state.notice_record = null;
            }
        });
        HF.state.notice_record = record;
        record.element.setAttribute('role', 'alertdialog');
        record.element.setAttribute('aria-modal', 'true');
        record.element.setAttribute('aria-label', HF.tr(titles[type]));
        append_window_notice(record, message, type);
        HF.window_manager.show_modal_overlay(record);
        if (auto_close > 0) {
            setTimeout(function() { HF.window_manager.close(record); }, auto_close);
        }
        return record;
    };

    
    HF.confirm_window = function confirm_window(options) {
        options = options || {};
        if (!HF.window_manager) {
            return Promise.resolve(true);
        }
        return new Promise(function(resolve) {
            var body = HF.Util.createElement('div', 'fm-confirm-body');
            var msg = HF.Util.createElement('div', 'fm-confirm-message', String(options.message || ''));
            var actions = HF.Util.createElement('div', 'fm-confirm-actions');
            body.appendChild(msg);
            body.appendChild(actions);
            var settled = false;
            var record = null;
            function finish(value) {
                if (settled) {
                    return;
                }
                settled = true;
                if (record) {
                    HF.window_manager.close(record);
                }
                resolve(value);
            }
            record = HF.window_manager.create({
                title: options.title || HF.tr('Confirm'),
                icon: 'file',
                className: 'fm-confirm-window',
                content: body,
                width: 440,
                height: 160,
                minWidth: 280,
                minHeight: 120,
                persistSize: false,
                beforeClose: function() {
                    finish(false);
                    return true;
                }
            });
            HF.window_manager.show_modal_overlay(record);
            var cancel_btn = HF.wm_window_action(options.cancel_label || HF.tr('Cancel'), false);
            var ok_btn = HF.wm_window_action(options.confirm_label || HF.tr('Confirm'), true);
            cancel_btn.addEventListener('click', function() { finish(false); });
            ok_btn.addEventListener('click', function() { finish(true); });
            actions.appendChild(cancel_btn);
            actions.appendChild(ok_btn);
        });
    };

    HF.prompt_credentials = function prompt_credentials(options) {
        options = options || {};
        var dialog = document.getElementById('fm_system_access_dialog');
        if (!dialog) return Promise.resolve(null);
        return new Promise(function(resolve) {
            var password = document.getElementById('fm_system_access_password');
            var totp = document.getElementById('fm_system_access_totp');
            var totpRow = document.getElementById('fm_system_access_totp_row');
            var timeoutBox = document.getElementById('fm_system_access_timeout');
            var timeoutEnabled = document.getElementById('fm_system_access_timeout_enabled');
            var timeoutMinutes = document.getElementById('fm_system_access_timeout_minutes');
            var statusNode = document.getElementById('fm_system_access_status');
            var verifyButton = document.getElementById('fm_system_access_confirm');
            var cancelButton = document.getElementById('fm_system_access_cancel');
            var titleNode = document.getElementById('fm_system_access_title');
            var messageNode = document.getElementById('fm_system_access_path');
            var totpLabel = document.getElementById('fm_system_access_totp_label');
            var busyNodes = [password, totp, timeoutEnabled, timeoutMinutes, verifyButton, cancelButton];
            var finished = false;
            if (typeof dialog._credentialsFinish === 'function') dialog._credentialsFinish(null);
            function setStatus(message, kind) {
                statusNode.textContent = message || '';
                statusNode.classList.toggle('is-error', kind === 'error');
                statusNode.classList.toggle('is-loading', kind === 'loading');
                statusNode.setAttribute('aria-busy', kind === 'loading' ? 'true' : 'false');
            }
            function setBusy(active) {
                busyNodes.forEach(function(node) { if (node) node.disabled = active; });
                if (!active && timeoutEnabled) timeoutMinutes.disabled = timeoutBox.hidden || !timeoutEnabled.checked;
                verifyButton.textContent = active
                    ? (HF.labels.verifying || HF.tr('Verifying…'))
                    : HF.tr(options.confirm || 'Verify');
            }
            function closeDialog() {
                if (dialog._fmWindow && HF.window_manager) HF.window_manager.close(dialog._fmWindow);
                else dialog.style.display = 'none';
            }
            function finish(value) {
                if (finished) return;
                finished = true;
                dialog._credentialsFinish = null;
                dialog._systemAccessResolve = null;
                setBusy(false);
                setStatus('', '');
                password.value = '';
                totp.value = '';
                closeDialog();
                resolve(value);
            }
            function fail(error) {
                var message = error && error.message || HF.labels.operation_failed || HF.tr('That did not work');
                setBusy(false);
                setStatus(message, 'error');
                password.focus();
            }
            dialog._credentialsFinish = finish;
            dialog._systemAccessResolve = function() { finish(null); };
            titleNode.textContent = HF.tr(options.title || 'Security verification');
            messageNode.textContent = options.message ? HF.tr(options.message) : '';
            messageNode.style.display = options.message ? '' : 'none';
            totpRow.hidden = options.totp === false;
            if (totpLabel) {
                totpLabel.textContent = HF.tr(options.totp === true
                    ? 'Authenticator code'
                    : 'Two-factor code, if enabled');
            }
            var passwordLabel = dialog.querySelector('label[for="fm_system_access_password"]');
            if (passwordLabel) passwordLabel.textContent = HF.tr('Password');
            if (timeoutBox) {
                var autoLock = timeoutBox.querySelector('.fm-system-access-timeout-setting .fm-form-label');
                if (autoLock) autoLock.textContent = HF.tr('Auto-lock after timeout');
                var minutesLabel = dialog.querySelector('label[for="fm_system_access_timeout_minutes"]');
                if (minutesLabel) minutesLabel.textContent = HF.tr('Timeout duration in minutes');
            }
            if (cancelButton) cancelButton.textContent = HF.tr('Cancel');
            timeoutBox.hidden = options.extra !== 'timeout';
            if (options.extra === 'timeout') {
                var defaults = options.timeoutDefaults || {};
                timeoutEnabled.checked = defaults.timeout_enabled !== false;
                var savedMinutes = Number(defaults.timeout_minutes);
                timeoutMinutes.value = Number.isInteger(savedMinutes) && savedMinutes >= 1 && savedMinutes <= 10080
                    ? String(savedMinutes) : '15';
                timeoutMinutes.disabled = !timeoutEnabled.checked;
                timeoutEnabled.onchange = function() { timeoutMinutes.disabled = !timeoutEnabled.checked; };
            }
            cancelButton.onclick = function() { finish(null); };
            verifyButton.onclick = function() {
                if (verifyButton.disabled) return;
                var creds = { password: password.value, totp_code: totp.value };
                if (!creds.password) {
                    setStatus(HF.tr('Enter your current password'), 'error');
                    password.focus();
                    return;
                }
                if (options.totp === true && !String(creds.totp_code || '').trim()) {
                    setStatus(HF.tr('Enter the six-digit code'), 'error');
                    totp.focus();
                    return;
                }
                if (options.extra === 'timeout') {
                    var minutes = Number(timeoutMinutes.value);
                    if (timeoutEnabled.checked && (!Number.isInteger(minutes) || minutes < 1 || minutes > 10080)) {
                        setStatus(HF.tr('Enter a timeout from 1 to 10080 minutes.'), 'error');
                        return;
                    }
                    creds.timeout_enabled = timeoutEnabled.checked;
                    creds.timeout_minutes = minutes;
                }
                if (!options.verify) {
                    finish(creds);
                    return;
                }
                setBusy(true);
                setStatus(HF.labels.verifying || HF.tr('Verifying…'), 'loading');
                Promise.resolve()
                    .then(function() { return options.verify(creds); })
                    .then(function() { finish(creds); }, fail);
            };
            setBusy(false);
            setStatus('', '');
            HF.open_modal('fm_system_access_dialog');
            password.focus();
        });
    };

    HF.set_status = function set_status(message, type, duration) {
        if (!message) {
            return;
        }
        if (message === HF.labels.system_folder_blocked) {
            if (HF.state.system_blocked_notified) {
                return;
            }
            HF.state.system_blocked_notified = true;
            HF.notify(message, 'notice');
            return;
        }
        var resolved_type = type || 'notice';
        var auto = resolved_type === 'error' || resolved_type === 'warning' ? 0 : HF.status_timeout(resolved_type, duration);
        HF.notify(message, resolved_type, auto);
    }

    HF.set_warning_status = function set_warning_status(message) {
        HF.set_status(message, 'warning');
    }

    HF.set_error_status = function set_error_status(message) {
        HF.set_status(message, 'error');
    }

    HF.set_write_block_status = function set_write_block_status(message) {
        HF.set_status(message, String(message || '').indexOf('5%') >= 0 ? 'error' : 'warning');
    }

    HF.request_write = function request_write(url, data, success_message, on_ok, on_error, request_options) {
        function retryAccess(res, onDeny) {
            if (request_options && request_options.systemAccessRetried) return false;
            var options = Object.assign({}, request_options || {}, { systemAccessRetried: true });
            return HF.retry_system_access(url, data, res, function() {
                HF.request_write(url, data, success_message, on_ok, on_error, options);
            }, onDeny);
        }
        HF.file_ajax({
            url: url,
            type: 'POST',
            data: data,
            dataType: 'json',
            timeout: request_options && request_options.timeout || 0,
            success: function(res) {
                if (!res || res.code !== 0) {
                    if (retryAccess(res, function() {
                        if (!request_options || !request_options.quietError) HF.set_error_status((res && res.message) || HF.labels.operation_failed);
                        if (on_error) {
                            on_error((res && res.message) || HF.labels.operation_failed, res);
                        }
                    })) return;
                    if (!request_options || !request_options.quietError) HF.set_error_status((res && res.message) || HF.labels.operation_failed);
                    if (on_error) {
                        on_error((res && res.message) || HF.labels.operation_failed, res);
                    }
                    return;
                }
                HF.set_status(success_message, 'success');
                if (on_ok) {
                    on_ok(res.data || {});
                }
            },
            error: function(xhr) {
                var response = HF.response_json(xhr);
                if (retryAccess(response, function() {
                    var denyMessage = HF.upload_error_message(xhr, HF.labels.operation_failed);
                    if (!request_options || !request_options.quietError) HF.set_error_status(denyMessage);
                    if (on_error) {
                        on_error(denyMessage, HF.response_json(xhr));
                    }
                })) return;
                var message = HF.upload_error_message(xhr, HF.labels.operation_failed);
                if (!request_options || !request_options.quietError) HF.set_error_status(message);
                if (on_error) {
                    on_error(message, HF.response_json(xhr));
                }
            }
        });
    }

    HF.archive_error_message = function archive_error_message(res, fallback) {
        var data = (res && res.data) || {};
        if (data.missing_tool) {
            return HF.format_label(HF.labels.archive_missing_tool_install, data.missing_tool);
        }
        var message = (res && res.message) || fallback || HF.labels.archive_failed;
        if (data.failed_path) {
            message = message + ' (' + data.failed_path + ')';
        }
        return message;
    }

    HF.request_archive_write = function request_archive_write(url, data, on_ok, on_error, attempted) {
        data = Object.assign({}, data);
        attempted = attempted || new Set();
        function finish_error(res) {
            if (res && res.data && res.data.missing_tool && res.data.dependency_preflight === true && res.data.outcome_unknown !== true) {
                var tool = res.data.missing_tool;
                res.data.dependency_attempted = attempted.has(tool);
                res.data.remote_retry = function() {
                    attempted.add(tool);
                    HF.request_archive_write(url, data, on_ok, on_error, attempted);
                };
            }
            if (typeof on_error === 'function') {
                on_error(res);
            } else {
                HF.set_error_status(HF.archive_error_message(res, HF.labels.archive_failed));
            }
        }
        function handle_error(res) {
            if (!attempted.systemAccessRetried && HF.retry_system_access(url, data, res, function() {
                attempted.systemAccessRetried = true;
                HF.request_archive_write(url, data, on_ok, on_error, attempted);
            }, function() { finish_error(res); })) return;
            finish_error(res);
        }
        HF.file_ajax({
            url: url,
            type: 'POST',
            data: data,
            dataType: 'json',
            success: function(res) {
                if (!res || res.code !== 0) {
                    handle_error(res);
                    return;
                }
                if (on_ok) {
                    on_ok(res.data || {});
                }
            },
            error: function(xhr) {
                handle_error(HF.response_json(xhr) || {});
            }
        });
    }

    HF.clear_node = function clear_node(node) {
        while (node.firstChild) {
            node.removeChild(node.firstChild);
        }
    }

    HF.icon_url = function icon_url(name) {
        if (typeof window.HARBOR_ICON_URL === 'function') return window.HARBOR_ICON_URL(name);
        var manifest = window.HARBOR_ICONS || {};
        var key = String(name || '').replace(/^.*\//, '').replace(/\.svg$/i, '').toLowerCase();
        if (manifest.icons && manifest.icons[key]) return manifest.icons[key];
        if (manifest.icons && manifest.icons[manifest.fallback]) return manifest.icons[manifest.fallback];
        return 'none';
    }

    HF.is_child_path = function is_child_path(path, root) {
        return path === root || path.indexOf(root + '/') === 0;
    }

    HF.view_mode_to_value = function view_mode_to_value(mode) {
        var modes = ['large', 'medium', 'small', 'list', 'details', 'tile'];
        var index = modes.indexOf(mode);
        return index >= 0 ? index : 1;
    }

    HF.value_to_view_mode = function value_to_view_mode(value) {
        var modes = ['large', 'medium', 'small', 'list', 'details', 'tile'];
        var index = Number(value);
        return modes[index] || 'medium';
    }

    HF.item_icon_name = function item_icon_name(item, kind) {
        if (item.icon_name) {
            return item.icon_name;
        }
        if (kind === 'drive') {
            return 'drive';
        }
        if (item.type === 'directory') {
            return 'folder';
        }
        if (item.preview === 'text' || item.preview === 'image' || item.preview === 'video' || item.preview === 'pdf') {
            return item.preview;
        }
        return 'file';
    }

    HF.normalize_integer_setting = function normalize_integer_setting(value, fallback) {
        var number = Number(value);
        return isNaN(number) ? fallback : Math.floor(number);
    }

    HF.format_size = function format_size(bytes) {
        var value = Number(bytes || 0);
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var index = 0;
        while (value >= 1024 && index < units.length - 1) {
            value = value / 1024;
            index++;
        }
        return value.toFixed(index === 0 ? 0 : 1) + ' ' + units[index];
    }

    HF.format_kb = function format_kb(kb) {
        return HF.format_size(Number(kb || 0) * 1024);
    }

    HF.format_speed = function format_speed(bytes_per_second) {
        var value = Number(bytes_per_second || 0);
        if (!isFinite(value) || value <= 0) {
            return '0 B/s';
        }
        return HF.format_size(value) + '/s';
    }

    HF.format_elapsed = function format_elapsed(seconds) {
        var total = Math.max(0, Math.floor(Number(seconds) || 0));
        var pad = function(value) { return value < 10 ? '0' + value : String(value); };
        var hours = Math.floor(total / 3600);
        var minutes = Math.floor((total % 3600) / 60);
        var secs = total % 60;
        if (hours) return hours + ':' + pad(minutes) + ':' + pad(secs);
        if (minutes) return minutes + ':' + pad(secs);
        return secs + 's';
    }

    HF.format_time = function format_time(timestamp) {
        if (!timestamp) {
            return '-';
        }
        var date = new Date(Number(timestamp) * 1000);
        if (isNaN(date.getTime())) {
            return '-';
        }
        var pad = function(value) { return value < 10 ? '0' + value : String(value); };
        return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate()) +
            ' ' + pad(date.getHours()) + ':' + pad(date.getMinutes());
    }

    HF.parent_directory = function parent_directory(path) {
        var value = String(path || '');
        if (!value || value === '/') {
            return '/';
        }
        var index = value.lastIndexOf('/');
        if (index <= 0) {
            return '/';
        }
        return value.substring(0, index) || '/';
    }

    HF.format_label = function format_label(template, value) {
        return String(template || '').replace(/%[ds]/, String(value));
    }

    HF.upload_error_message = function upload_error_message(xhr, fallback) {
        try {
            var response = JSON.parse(xhr.responseText || '{}');
            return response.message || fallback;
        } catch (error) {
            return fallback;
        }
    }

    HF.response_json = function response_json(xhr) {
        try {
            return JSON.parse(xhr.responseText || '{}');
        } catch (error) {
            return {};
        }
    }

    HF.localized_space_message = function localized_space_message(message) {
        return String(message || '').indexOf('5%') >= 0 ? HF.labels.space_less_than_50mb : message;
    }
    HF.Util = HF.Util || {};
    HF.session_expired = function session_expired(message) {
        if (HF.state.session_expired) return;
        HF.state.session_expired = true;
        function goLogin() {
            if (HF.flush_last_directory) HF.flush_last_directory(true);
            var target = (window.HARBOR_CONFIG && window.HARBOR_CONFIG.login) || '/login';
            window.location.replace(target + (target.indexOf('?') >= 0 ? '&' : '?') + 'expired=1');
        }
        try {
            fetch('/api/v1/auth_status?_=' + Date.now(), {
                credentials: 'same-origin',
                cache: 'no-store'
            }).then(function (response) {
                return response.json();
            }).then(function (result) {
                if (result && result.data && result.data.authenticated === true) {
                    HF.state.session_expired = false;
                    return;
                }
                goLogin();
            }).catch(goLogin);
        } catch (error) {
            HF.state.session_expired = false;
            if (message) HF.notify(message, 'error');
        }
    };
    HF.Util.ajax = function (options) {
        var url = options.url || '';
        var type = (options.type || 'GET').toUpperCase();
        var query = '';
        if (options.data) {
            var parts = [];
            for (var key in options.data) {
                if (Object.prototype.hasOwnProperty.call(options.data, key) &&
                        options.data[key] !== undefined && options.data[key] !== null) {
                    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(options.data[key])));
                }
            }
            query = parts.join('&');
        }
        if (type === 'GET' && query) {
            url += (url.indexOf('?') >= 0 ? '&' : '?') + query;
        }
        if (options.cache === false || options.cache === 'no-store') {
            url += (url.indexOf('?') >= 0 ? '&' : '?') + '_=' + Date.now();
        }
        try {
            if (new URL(url, window.location.href).pathname.replace(/\/$/, '') === '/logout' &&
                    HF.flush_last_directory) HF.flush_last_directory(true);
        } catch (error) {}
        var xhr = new XMLHttpRequest();
        xhr.open(type, url, true);
        if (Number(options.timeout) > 0) xhr.timeout = Number(options.timeout);
        if (type === 'POST') {
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        }
        xhr.onload = function () {
            if (xhr.status === 401) {
                HF.session_expired();
                if (options.error) { options.error(xhr); }
                return;
            }
            if (xhr.status < 200 || xhr.status >= 300) {
                if (options.error) { options.error(xhr); }
                return;
            }
            var result = xhr.responseText;
            if (options.dataType === 'json') {
                try { result = JSON.parse(xhr.responseText); }
                catch (e) { if (options.error) { options.error(xhr); } return; }
            }
            if (options.success) { options.success(result); }
        };
        xhr.onerror = function () {
            if (options.error) { options.error(xhr); }
        };
        xhr.ontimeout = xhr.onerror;
        xhr.send(type === 'POST' ? query : null);
    };
    HF.Util.trim = function (value) { return String(value == null ? '' : value).trim(); };

    HF.Util.createHistory = function (limit, coalesce_ms) {
        var undoStack = [];
        var redoStack = [];
        var max = limit || 100;
        var coalesce = coalesce_ms === undefined ? 800 : coalesce_ms;
        var lastCapture = 0;
        return {
            capture: function (snapshot) {
                redoStack.length = 0;
                var now = Date.now();
                if (coalesce > 0 && now - lastCapture < coalesce && undoStack.length) {
                    return; 
                }
                undoStack.push(snapshot);
                if (undoStack.length > max) {
                    undoStack.shift();
                }
                lastCapture = now;
            },
            undo: function (current) {
                if (!undoStack.length) { return null; }
                redoStack.push(current);
                lastCapture = 0;
                return undoStack.pop();
            },
            redo: function (current) {
                if (!redoStack.length) { return null; }
                undoStack.push(current);
                lastCapture = 0;
                return redoStack.pop();
            },
            canUndo: function () { return undoStack.length > 0; },
            canRedo: function () { return redoStack.length > 0; },
            reset: function () { undoStack.length = 0; redoStack.length = 0; lastCapture = 0; }
        };
    };
    HF.bind_horizontal_scroll = function bind_horizontal_scroll(node, options) {
        if (node._fmHorizontalScroll) return node._fmHorizontalScroll;
        options = options || {};
        node.classList.add('fm-horizontal-scroll');
        var drag = null, suppress_click = false;
        function scrollable() {
            return node.scrollWidth > node.clientWidth && (!options.enabled || options.enabled());
        }
        node.addEventListener('wheel', function(event) {
            if (event.ctrlKey || !scrollable()) return;
            var delta = Math.abs(event.deltaX) > Math.abs(event.deltaY) ? event.deltaX : event.deltaY;
            if (event.deltaMode === 1) delta *= 16;
            else if (event.deltaMode === 2) delta *= node.clientWidth;
            var previous = node.scrollLeft;
            node.scrollLeft += delta;
            if (node.scrollLeft !== previous) {
                event.preventDefault();
                event.stopPropagation();
            }
        }, { passive: false });
        function text_point(event) {
            var rect = node.getBoundingClientRect();
            var walker = document.createTreeWalker(node, 4), first = walker.nextNode(), last = first, next;
            if (!first) return null;
            while ((next = walker.nextNode())) last = next;
            if (event.clientY < rect.top || event.clientX < rect.left) return { node: first, offset: 0 };
            if (event.clientY > rect.bottom || event.clientX > rect.right) return { node: last, offset: last.length };
            var point, range;
            if (document.caretPositionFromPoint) {
                point = document.caretPositionFromPoint(event.clientX, event.clientY);
                if (point && node.contains(point.offsetNode)) return { node: point.offsetNode, offset: point.offset };
            } else if (document.caretRangeFromPoint) {
                range = document.caretRangeFromPoint(event.clientX, event.clientY);
                if (range && node.contains(range.startContainer)) return { node: range.startContainer, offset: range.startOffset };
            }
            return { node: last, offset: last.length };
        }
        function select_to(event) {
            var point = text_point(event), selection = window.getSelection();
            if (!point || !selection || !drag || !drag.anchor || !node.contains(drag.anchor.node)) return;
            selection.setBaseAndExtent(drag.anchor.node, drag.anchor.offset, point.node, point.offset);
        }
        function end_drag(event) {
            if (!drag || event && event.pointerId != null && event.pointerId !== drag.id) return;
            var previous = drag;
            drag = null;
            if (previous.active || previous.selecting) suppress_click = true;
            node.style.cursor = previous.cursor;
            node.style.userSelect = previous.select;
            if (node.hasPointerCapture(previous.id)) node.releasePointerCapture(previous.id);
            document.removeEventListener('pointermove', move_drag);
            document.removeEventListener('pointerup', end_drag);
            document.removeEventListener('pointercancel', end_drag);
            node.removeEventListener('lostpointercapture', end_drag);
            window.removeEventListener('blur', end_drag);
        }
        function move_drag(event) {
            if (!drag || event.pointerId !== drag.id) return;
            if (!node.isConnected || !(event.buttons & 1)) { end_drag(event); return; }
            var delta = event.clientX - drag.x;
            if (drag.selecting) {
                event.preventDefault();
                select_to(event);
                return;
            }
            if (!drag.active) {
                var distance = options.dragAnywhere ? Math.hypot(delta, event.clientY - drag.y) : Math.abs(delta);
                if (distance < 6) return;
                drag.active = true;
                node.setPointerCapture(drag.id);
                node.style.cursor = 'grabbing';
            }
            event.preventDefault();
            node.scrollLeft = drag.left - delta;
        }
        node.addEventListener('pointerdown', function(event) {
            if (event.defaultPrevented) return;
            suppress_click = false;
            if (options.mouseDrag === false || event.pointerType !== 'mouse' || event.button !== 0 ||
                    options.dragEnabled && !options.dragEnabled() || !scrollable() && !options.dragAnywhere) return;
            end_drag();
            var selecting = !!(options.selectText && event.shiftKey);
            if (options.selectText) {
                event.preventDefault();
                node.focus({ preventScroll: true });
                var selection = window.getSelection();
                if (!selecting && selection && (node.contains(selection.anchorNode) || node.contains(selection.focusNode))) selection.removeAllRanges();
            }
            drag = { id: event.pointerId, x: event.clientX, y: event.clientY, left: node.scrollLeft,
                active: false, cursor: node.style.cursor, select: node.style.userSelect, selecting: selecting,
                anchor: selecting ? text_point(event) : null };
            node.style.userSelect = selecting ? 'text' : 'none';
            if (selecting) {
                node.setPointerCapture(drag.id);
                select_to(event);
            }
            document.addEventListener('pointermove', move_drag, { passive: false });
            document.addEventListener('pointerup', end_drag);
            document.addEventListener('pointercancel', end_drag);
            node.addEventListener('lostpointercapture', end_drag);
            window.addEventListener('blur', end_drag);
        });
        if (options.selectText) {
            node.title = HF.tr('Drag to scroll horizontally; Shift-drag to select text');
            node.addEventListener('dragstart', function(event) {
                event.preventDefault();
                event.stopPropagation();
            });
        }
        node.addEventListener('click', function(event) {
            if (!suppress_click || !event.detail) return;
            suppress_click = false;
            event.preventDefault();
            event.stopImmediatePropagation();
        }, true);
        node.addEventListener('keydown', function(event) {
            if (event.target !== node || event.ctrlKey || event.metaKey || event.altKey || event.shiftKey || !scrollable()) return;
            if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
            var previous = node.scrollLeft;
            node.scrollLeft += event.key === 'ArrowLeft' ? -40 : 40;
            if (node.scrollLeft !== previous) {
                event.preventDefault();
                event.stopPropagation();
            }
        });
        node._fmHorizontalScroll = { cancel: end_drag };
        return node._fmHorizontalScroll;
    };

    HF.Util.createElement = function (tag, class_name, text) {
        var node = document.createElement(tag);
        if (class_name) { node.className = class_name; }
        if (text !== undefined && text !== null) { node.textContent = text; }
        return node;
    };

    HF.Util.request_json = HF.request_json;
    HF.Util.request_write = HF.request_write;
    HF.Util.request_archive_write = HF.request_archive_write;
    HF.Util.set_status = HF.set_status;
    HF.Util.set_warning_status = HF.set_warning_status;
    HF.Util.set_error_status = HF.set_error_status;
    HF.Util.set_write_block_status = HF.set_write_block_status;
    HF.Util.status_timeout = HF.status_timeout;
    HF.Util.format_size = HF.format_size;
    HF.Util.format_kb = HF.format_kb;
    HF.Util.format_speed = HF.format_speed;
    HF.Util.format_time = HF.format_time;
    HF.Util.format_label = HF.format_label;
    HF.Util.parent_directory = HF.parent_directory;
    HF.Util.icon_url = HF.icon_url;
    HF.Util.item_icon_name = HF.item_icon_name;
    HF.Util.is_child_path = HF.is_child_path;
    HF.Util.view_mode_to_value = HF.view_mode_to_value;
    HF.Util.value_to_view_mode = HF.value_to_view_mode;
    HF.Util.normalize_integer_setting = HF.normalize_integer_setting;
    HF.Util.response_json = HF.response_json;
    HF.Util.upload_error_message = HF.upload_error_message;
    HF.Util.localized_space_message = HF.localized_space_message;
    HF.Util.archive_error_message = HF.archive_error_message;
    HF.Util.clear_node = HF.clear_node;
})(window.HarborFile = window.HarborFile || {});
