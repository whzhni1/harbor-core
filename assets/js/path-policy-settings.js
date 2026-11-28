(function (HF) {
    'use strict';

    function byId(id) { return document.getElementById(id); }
    var lastMessage = '';
    var lastMessageError = false;
    function showMessage(text, isError) {
        lastMessage = text || '';
        lastMessageError = !!isError;
        var node = byId('fm_root_policy_message');
        if (!node) return;
        var visibleText = lastMessage && window.HARBOR_T ? window.HARBOR_T(lastMessage) : lastMessage;
        node.textContent = visibleText;
        node.classList.toggle('is-error', lastMessageError);
    }
    function reportSaveError(text) {
        showMessage(text, true);
        if (HF.set_status) {
            HF.set_status(window.HARBOR_T ? window.HARBOR_T(text) : text, 'error');
        }
    }
    document.addEventListener('harbor:i18n', function () {
        showMessage(lastMessage, lastMessageError);
    });
    function toggleMode() {
        var mode = byId('fm_root_policy_mode').value;
        var managed = !!(HF.root_policy_state && HF.root_policy_state.managed_by_cli === true);
        var allowRow = byId('fm_root_allowlist_row');
        var denyRow = byId('fm_root_denylist_row');
        var allowInput = byId('fm_root_allowlist');
        var denyInput = byId('fm_root_denylist');
        allowRow.hidden = mode !== 'allowlist';
        denyRow.hidden = mode !== 'denylist';
        allowInput.disabled = managed || mode !== 'allowlist';
        denyInput.disabled = managed || mode !== 'denylist';
    }
    function render(data) {
        HF.root_policy_state = data || {};
        byId('fm_root_policy_mode').value = data.policy || 'unrestricted';
        byId('fm_root_allowlist').value = (data.roots || []).join('\n');
        byId('fm_root_denylist').value = (data.excluded_roots || []).join('\n');
        byId('fm_root_policy_mode').disabled = data.managed_by_cli === true;
        byId('fm_root_allowlist').disabled = data.managed_by_cli === true;
        byId('fm_root_denylist').disabled = data.managed_by_cli === true;
        byId('fm_root_policy_save').disabled = data.managed_by_cli === true;
        showMessage(data.managed_by_cli
            ? 'The active path policy is set by command-line options and cannot be changed here.'
            : '', false);
        toggleMode();
    }
    HF.refresh_root_policy_settings = function refresh_root_policy_settings() {
        HF.Util.ajax({
            url: HF.api.root_policy,
            type: 'GET',
            dataType: 'json',
            success: function (res) {
                if (res && res.code === 0) render(res.data || {});
                else showMessage((res && res.message) || 'Cannot load path policy', true);
            },
            error: function (xhr) {
                var response = HF.response_json ? HF.response_json(xhr) : null;
                showMessage((response && response.message) || 'Cannot load path policy', true);
            }
        });
    };

    function lines(id) {
        return byId(id).value.split(/\r?\n/).map(function (line) { return line.trim(); }).filter(Boolean);
    }
    function save() {
        var button = byId('fm_root_policy_save');
        if (button.disabled) return;
        var mode = byId('fm_root_policy_mode').value;
        var roots = lines('fm_root_allowlist');
        var excluded = lines('fm_root_denylist');
        if (mode === 'allowlist' && !roots.length) { reportSaveError('Add at least one allowed root directory.'); return; }
        if (mode === 'denylist' && !excluded.length) { reportSaveError('Add at least one blocked root directory.'); return; }
        var payload = { policy: mode };
        if (mode === 'allowlist') payload.roots = JSON.stringify(roots);
        if (mode === 'denylist') payload.excluded_roots = JSON.stringify(excluded);
        button.disabled = true;
        HF.prompt_credentials({
            title: 'Security verification',
            message: 'Enter your password before saving.',
            totp: !!(HF.root_policy_state && HF.root_policy_state.totp_required),
            confirm: 'Save',
            verify: function (creds) {
                payload.current_password = creds.password;
                payload.totp_code = creds.totp_code;
                return new Promise(function (ok, fail) {
                    HF.Util.ajax({
                        url: HF.api.save_root_policy,
                        type: 'POST',
                        data: payload,
                        dataType: 'json',
                        success: function (res) {
                            if (!res || res.code !== 0) {
                                fail(new Error((res && res.message) || 'Cannot save path policy'));
                                return;
                            }
                            render(res.data || {});
                            showMessage('', false);
                            var successText = HF.labels.settings_saved || 'Settings saved';
                            var translatedSuccess = window.HARBOR_T ? window.HARBOR_T(successText) : successText;
                            if (HF.notify) HF.notify(translatedSuccess, 'success');
                            else if (HF.set_status) HF.set_status(translatedSuccess, 'success');
                            ok(res);
                        },
                        error: function (xhr) {
                            var response = HF.response_json ? HF.response_json(xhr) : null;
                            fail(new Error((response && response.message) || 'Cannot save path policy'));
                        }
                    });
                });
            }
        }).then(function () {
            button.disabled = false;
        });
    }

    HF.bind_root_policy_settings = function bind_root_policy_settings() {
        var mode = byId('fm_root_policy_mode');
        var saveButton = byId('fm_root_policy_save');
        var reloadButton = byId('fm_root_policy_reload');
        if (!mode || !saveButton || !reloadButton || mode._rootPolicyBound) return;
        mode._rootPolicyBound = true;
        mode.addEventListener('change', toggleMode);
        saveButton.addEventListener('click', save);
        reloadButton.addEventListener('click', HF.refresh_root_policy_settings);
    };
})(window.HarborFile = window.HarborFile || {});
