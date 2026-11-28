(function (HF) {
    'use strict';

    function by_id(id) { return document.getElementById(id); }
    function tr(text) { return HF.tr ? HF.tr(text) : text; }
    function value_of(id) {
        var node = by_id(id);
        return node ? String(node.value == null ? '' : node.value) : '';
    }
    function clear_inputs(ids) {
        ids.forEach(function (id) {
            var node = by_id(id);
            if (node) node.value = '';
        });
    }
    function status(message, failed, loading) {
        var node = by_id('fm_security_status');
        if (node) {
            node.textContent = message || '';
            node.classList.toggle('is-error', !!failed);
            node.classList.toggle('is-loading', !!loading);
            node.setAttribute('aria-busy', loading ? 'true' : 'false');
        }
        if (failed && HF.notify) HF.notify(message || tr('That did not work'), 'error');
    }

    function button_busy(id, active) {
        var button = by_id(id);
        if (!button) return;
        if (active) {
            if (!button.hasAttribute('data-original-label')) button.setAttribute('data-original-label', button.textContent);
            button.disabled = true;
            button.textContent = tr('Verifying…');
        } else {
            button.disabled = false;
            if (button.hasAttribute('data-original-label')) {
                button.textContent = button.getAttribute('data-original-label');
                button.removeAttribute('data-original-label');
            }
        }
    }

    HF.security_state = HF.security_state || {};
    HF.security_totp_setup_active = HF.security_totp_setup_active === true;

    HF.security_cancel_totp_setup = function security_cancel_totp_setup(on_complete) {
        var state = HF.security_state || {};
        var wasPending = state.totp_pending === true;
        HF.security_totp_setup_active = false;
        state.totp_pending = false;
        var panel = by_id('fm_security_totp_setup');
        if (panel) panel.hidden = true;
        var qr = by_id('fm_security_totp_qr');
        if (qr) { qr.removeAttribute('src'); qr.hidden = true; }
        var secret = by_id('fm_security_totp_secret');
        if (secret) secret.textContent = '';
        var uri = by_id('fm_security_totp_uri');
        if (uri) uri.textContent = '';
        clear_inputs(['fm_security_totp_code', 'fm_security_totp_disable_code']);
        if (HF.security_totp_setup_inflight) {
            HF.security_totp_cancel_requested = true;
            render();
            if (on_complete) on_complete();
            return;
        }
        if (!wasPending || !HF.api || !HF.api.security_totp_cancel) {
            render();
            if (on_complete) on_complete();
            return;
        }
        HF.security_totp_cancel_inflight = true;
        HF.Util.ajax({
            url: HF.api.security_totp_cancel,
            type: 'POST',
            data: {},
            dataType: 'json',
            success: function (res) {
                HF.security_totp_cancel_inflight = false;
                if (res && res.code === 0) HF.security_state = res.data || HF.security_state;
                render();
                if (on_complete) on_complete();
            },
            error: function () {
                HF.security_totp_cancel_inflight = false;
                HF.refresh_security_settings();
                if (on_complete) on_complete();
            }
        });
        render();
    };

    function render() {
        var state = HF.security_state || {};
        var user = by_id('fm_security_username');
        if (HF.security_settings_reset_pending) {
            if (user) user.value = state.username || 'admin';
            clear_inputs([
                'fm_security_current_password',
                'fm_security_new_password',
                'fm_security_confirm_password',
                'fm_security_totp_code'
            ]);
            HF.security_settings_reset_pending = false;
        } else if (user && !user.value) {
            user.value = state.username || 'admin';
        }
        var enabled = state.totp_enabled === true;
        var pending = state.totp_pending === true;
        var setupActive = HF.security_totp_setup_active === true;
        var toggle = by_id('fm_security_totp_start');
        if (toggle) {
            toggle.checked = enabled || (pending && setupActive);
            toggle.disabled = HF.security_totp_cancel_inflight === true || HF.security_totp_setup_inflight === true || HF.security_totp_disable_inflight === true;
            toggle.setAttribute('aria-checked', toggle.checked ? 'true' : 'false');
        }
        if (pending && !setupActive && !HF.security_totp_cancel_inflight) {
            HF.security_cancel_totp_setup();
        }
        var desc = by_id('fm_security_totp_desc');
        if (desc) {
            desc.textContent = enabled
                ? tr('Enabled: signing in asks for the six-digit code from your authenticator app.')
                : tr('Adds a six-digit code from an authenticator app to the sign-in.');
        }
        var setup = by_id('fm_security_totp_setup');
        if (setup) setup.hidden = !(pending && setupActive && !enabled);
        var disablePanel = by_id('fm_security_totp_disable');
        if (disablePanel) disablePanel.hidden = true;
        var loggedIn = by_id('fm_security_logged_in');
        if (loggedIn) loggedIn.textContent = tr('Signed in as %s').replace('%s', state.username || 'admin');
        status(
            (state.password_set === false)
                ? tr('No password set yet: use Reset or the sign-in page to create one.')
                : '',
            false
        );
    }

    HF.refresh_security_settings = function refresh_security_settings() {
        if (!HF.api || !HF.api.security_state) return;
        HF.Util.ajax({
            url: HF.api.security_state,
            type: 'GET',
            data: { _: Date.now() },
            dataType: 'json',
            success: function (res) {
                if (res && res.code === 0) {
                    HF.security_state = res.data || {};
                    render();
                }
            }
        });
    };

    function applied(res, message) {
        if (res && res.code === 0) {
            HF.security_state = res.data || HF.security_state;
            render();
            if (message && HF.set_status) HF.set_status(message, 'success');
            return true;
        }
        status((res && res.message) || tr('That did not work'), true);
        return false;
    }

    HF.security_save_account = function security_save_account() {
        if (by_id('fm_settings_security_save') && by_id('fm_settings_security_save').disabled) return;
        var current = value_of('fm_security_current_password');
        var username = value_of('fm_security_username').trim();
        var newPassword = value_of('fm_security_new_password');
        var confirmPassword = value_of('fm_security_confirm_password');
        var oldUsername = (HF.security_state && HF.security_state.username) || 'admin';
        var usernameChanged = username !== oldUsername;
        var passwordChanged = !!newPassword;
        if (!usernameChanged && !passwordChanged) {
            if (HF.set_status) HF.set_status(tr('No account changes to save'), 'notice');
            return;
        }
        if (!current && HF.security_state && HF.security_state.password_set !== false) {
            return status(tr('Enter your current password'), true);
        }
        if (usernameChanged && !username) {
            return status(tr('Enter a username'), true);
        }
        if (passwordChanged && newPassword !== confirmPassword) {
            return status(tr('The two passwords do not match'), true);
        }
        status(tr('Verifying…'), false, true);
        button_busy('fm_settings_security_save', true);
        HF.Util.ajax({
            url: HF.api.security_account,
            type: 'POST',
            data: {
                current_password: current,
                username: usernameChanged ? username : '',
                new_password: newPassword,
                confirm_password: confirmPassword
            },
            dataType: 'json',
            success: function (res) {
                button_busy('fm_settings_security_save', false);
                if (applied(res, tr('Account settings saved.'))) {
                    clear_inputs([
                        'fm_security_current_password',
                        'fm_security_new_password',
                        'fm_security_confirm_password'
                    ]);
                }
            },
            error: function (xhr) {
                button_busy('fm_settings_security_save', false);
                var response = HF.response_json ? HF.response_json(xhr) : null;
                status(response && response.message || tr('Cannot save account settings'), true);
            }
        });
    };

    HF.security_totp_setup = function security_totp_setup() {
        var toggle = by_id('fm_security_totp_start');
        HF.prompt_credentials({
            title: 'Security verification',
            message: tr('Enter your current password'),
            totp: false,
            confirm: 'Verify'
        }).then(function (creds) {
            if (!creds) {
                if (toggle) toggle.checked = false;
                render();
                return;
            }
            begin_totp_setup(creds.password);
        });
    };

    function begin_totp_setup(password) {
        HF.security_totp_setup_inflight = true;
        status(tr('Verifying…'), false, true);
        HF.security_totp_cancel_requested = false;
        var setupRequest = (HF.security_totp_setup_request || 0) + 1;
        HF.security_totp_setup_request = setupRequest;
        var toggle = by_id('fm_security_totp_start');
        if (toggle) toggle.disabled = true;
        HF.Util.ajax({
            url: HF.api.security_totp_setup,
            type: 'POST',
            data: { current_password: password },
            dataType: 'json',
            success: function (res) {
                HF.security_totp_setup_inflight = false;
                if (!res || res.code !== 0) {
                    HF.security_totp_cancel_requested = false;
                    render();
                    status((res && res.message) || tr('Cannot start the two-factor setup'), true);
                    return;
                }
                var data = res.data || {};
                HF.security_state = data.state || HF.security_state;
                if (HF.security_totp_cancel_requested || setupRequest !== HF.security_totp_setup_request) {
                    HF.security_totp_cancel_requested = false;
                    HF.security_totp_setup_active = true;
                    HF.security_cancel_totp_setup();
                    return;
                }
                HF.security_totp_setup_active = true;
                var secret = by_id('fm_security_totp_secret');
                if (secret) secret.textContent = data.secret || '';
                var uri = by_id('fm_security_totp_uri');
                if (uri) uri.textContent = data.otpauth_url || '';
                var qr = by_id('fm_security_totp_qr');
                if (qr && data.otpauth_url && typeof window.qrcode === 'function') {
                    try {
                        var code = window.qrcode(0, 'M');
                        code.addData(data.otpauth_url);
                        code.make();
                        qr.src = code.createDataURL(6, 4);
                        qr.hidden = false;
                    } catch (e) {
                        qr.removeAttribute('src');
                        qr.hidden = true;
                    }
                }
                var panel = by_id('fm_security_totp_setup');
                if (panel) panel.hidden = false;
                HF.security_state = data.state || HF.security_state;
                clear_inputs(['fm_security_current_password']);
                render();
            },
            error: function (xhr) {
                HF.security_totp_setup_inflight = false;
                var cancelled = HF.security_totp_cancel_requested;
                HF.security_totp_cancel_requested = false;
                if (!cancelled) {
                    var response = HF.response_json ? HF.response_json(xhr) : null;
                    render();
                    status(response && response.message || tr('Cannot start the two-factor setup'), true);
                } else {
                    render();
                }
            }
        });
    };

    HF.security_totp_confirm = function security_totp_confirm() {
        if (by_id('fm_security_totp_confirm') && by_id('fm_security_totp_confirm').disabled) return;
        var code = value_of('fm_security_totp_code');
        if (!code) return status(tr('Enter the six-digit code'), true);
        status(tr('Verifying…'), false, true);
        button_busy('fm_security_totp_confirm', true);
        HF.Util.ajax({
            url: HF.api.security_totp_enable,
            type: 'POST',
            data: { code: code },
            dataType: 'json',
            success: function (res) {
                button_busy('fm_security_totp_confirm', false);
                if (res && res.code === 0) HF.security_totp_setup_active = false;
                if (applied(res, tr('Two-factor authentication is on.'))) {
                    clear_inputs(['fm_security_totp_code']);
                    var panel = by_id('fm_security_totp_setup');
                    if (panel) panel.hidden = true;
                    var qr = by_id('fm_security_totp_qr');
                    if (qr) { qr.removeAttribute('src'); qr.hidden = true; }
                    var secret = by_id('fm_security_totp_secret');
                    if (secret) secret.textContent = '';
                    var uri = by_id('fm_security_totp_uri');
                    if (uri) uri.textContent = '';
                }
            },
            error: function () {
                button_busy('fm_security_totp_confirm', false);
                status(tr('Cannot enable the second factor'), true);
            }
        });
    };

    HF.security_totp_disable = function security_totp_disable() {
        var toggle = by_id('fm_security_totp_start');
        HF.prompt_credentials({
            title: 'Security verification',
            message: tr('Enter the six-digit code to turn off two-factor authentication.'),
            totp: true,
            confirm: 'Verify',
            verify: function (creds) {
                return new Promise(function (ok, fail) {
                    HF.security_totp_disable_inflight = true;
                    HF.Util.ajax({
                        url: HF.api.security_totp_disable,
                        type: 'POST',
                        data: { password: creds.password, code: creds.totp_code },
                        dataType: 'json',
                        success: function (res) {
                            HF.security_totp_disable_inflight = false;
                            if (applied(res, tr('Two-factor authentication is off.'))) {
                                HF.security_totp_setup_active = false;
                                clear_inputs(['fm_security_current_password', 'fm_security_totp_code', 'fm_security_totp_disable_code']);
                                ok(res);
                            } else {
                                fail(new Error((res && res.message) || tr('Cannot disable the second factor')));
                            }
                        },
                        error: function () {
                            HF.security_totp_disable_inflight = false;
                            fail(new Error(tr('Cannot disable the second factor')));
                        }
                    });
                });
            }
        }).then(function (creds) {
            if (!creds) {
                if (toggle) toggle.checked = true;
                render();
            }
        });
    };

})(window.HarborFile);

(function (HF) {
    'use strict';

    function by_id(id) { return document.getElementById(id); }
    function clear_inputs(ids) {
        ids.forEach(function (id) {
            var node = by_id(id);
            if (node) node.value = '';
        });
    }

    function on(id, event, handler) {
        var node = by_id(id);
        if (node) node.addEventListener(event, handler);
    }

    function cancel_security_dialog(event) {
        if (event) {
            event.preventDefault();
            event.stopImmediatePropagation();
        }
        var username = by_id('fm_security_username');
        if (username) username.value = (HF.security_state && HF.security_state.username) || 'admin';
        HF.security_settings_reset_pending = false;
        clear_inputs([
            'fm_security_current_password',
            'fm_security_new_password',
            'fm_security_confirm_password',
            'fm_security_totp_code',
            'fm_security_totp_disable_code'
        ]);
        if (HF.security_totp_setup_inflight) {
            HF.security_totp_cancel_requested = true;
            HF.security_totp_setup_active = false;
            HF.close_modal();
        } else if (HF.security_state && HF.security_state.totp_pending === true && HF.security_state.totp_enabled !== true) {
            HF.security_cancel_totp_setup(function () { HF.close_modal(); });
        } else {
            HF.security_totp_setup_active = false;
            var panel = by_id('fm_security_totp_setup');
            if (panel) panel.hidden = true;
            var qr = by_id('fm_security_totp_qr');
            if (qr) { qr.removeAttribute('src'); qr.hidden = true; }
            var secret = by_id('fm_security_totp_secret');
            if (secret) secret.textContent = '';
            var uri = by_id('fm_security_totp_uri');
            if (uri) uri.textContent = '';
            HF.close_modal();
        }
    }

    HF.bind_security_settings = function bind_security_settings() {
        on('fm_security_totp_start', 'change', function () {
            var state = HF.security_state || {};
            if (this.checked) {
                if (state.totp_enabled !== true && state.totp_pending !== true) HF.security_totp_setup();
            } else if (HF.security_totp_setup_inflight) {
                HF.security_totp_cancel_requested = true;
            } else if (state.totp_pending === true && state.totp_enabled !== true) {
                HF.security_cancel_totp_setup();
            } else if (state.totp_enabled === true) {
                HF.security_totp_disable();
            }
        });
        on('fm_security_totp_confirm', 'click', function () {
            HF.security_totp_confirm();
        });
        var settingsClose = document.querySelector('#fm_settings_dialog .fm-dialog-close');
        if (settingsClose) settingsClose.addEventListener('click', cancel_security_dialog, true);
        on('fm_security_totp_code', 'keydown', function (event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                HF.security_totp_confirm();
            }
        });
        on('fm_settings_security_save', 'click', HF.security_save_account);
        on('fm_settings_security_cancel', 'click', cancel_security_dialog);
        on('fm_security_logout', 'click', function () {
            HF.Util.ajax({
                url: '/logout',
                type: 'POST',
                data: {},
                dataType: 'json',
                success: function () {
                    if (HF.flush_last_directory) HF.flush_last_directory(true);
                    var target = (window.HARBOR_CONFIG && window.HARBOR_CONFIG.login) || '/login';
                    window.location.replace(target);
                }
            });
        });
    };
})(window.HarborFile);
