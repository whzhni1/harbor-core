
(function (HF) {
    'use strict';

    HF.update_language = function update_language() {
        return String(document.documentElement.lang || '').trim().toLowerCase().replace(/_/g, '-');
    };

    HF.set_update_operations_visible = function set_update_operations_visible(visible) {
        ['fm_about_latest_label', 'fm_about_latest_row', 'fm_about_mirror_label', 'fm_about_mirror_row'].forEach(function (id) {
            var node = document.getElementById(id);
            if (node) node.hidden = !visible;
        });
        if (!visible) {
            var button = document.getElementById('fm_update_start');
            if (button) button.style.display = 'none';
        }
    };

    HF.reset_update_result = function reset_update_result() {
        HF.state.update_epoch = (HF.state.update_epoch || 0) + 1;
        var latest = document.getElementById('fm_about_latest');
        var btn = document.getElementById('fm_update_start');
        if (latest) {
            latest.textContent = '…';
        }
        if (btn) {
            btn.style.display = 'none';
        }
    };

    HF.load_current_version = function load_current_version() {
        var version = document.getElementById('fm_about_version');
        if (!version) {
            return;
        }
        HF.Util.ajax({
            url: HF.api.version,
            type: 'GET',
            dataType: 'json',
            timeout: 10000,
            success: function(res) {
                if (res && res.code === 0 && res.data && res.data.version) {
                    version.textContent = 'v' + res.data.version;
                } else {
                    version.textContent = '-';
                }
            },
            error: function() {
                version.textContent = '-';
            }
        });
    };

    HF.check_update = function check_update() {
        var latest = document.getElementById('fm_about_latest');
        var btn = document.getElementById('fm_update_start');
        var check = document.getElementById('fm_update_check');
        if (!latest) {
            return;
        }
        HF.load_current_version();
        HF.reset_update_result();
        var epoch = HF.state.update_epoch;
        check.disabled = true;
        HF.Util.ajax({
            url: HF.api.update_check,
            type: 'GET',
            data: { language: HF.update_language() },
            dataType: 'json',
            timeout: 30000,
            success: function(res) {
                check.disabled = false;
                if (epoch !== HF.state.update_epoch) {
                    return;
                }
                var data = (res && res.data) || {};
                if (data.supported === false) {
                    HF.set_update_operations_visible(false);
                    latest.textContent = '';
                    return;
                }
                if (data.supported === true) HF.set_update_operations_visible(true);
                if (!res || res.code !== 0) { latest.textContent = HF.labels.update_check_failed; return; }
                var from_mirror = data.mirror ? ' · ' + data.mirror : '';
                if (data.installable === false && data.latest && data.has_update) {
                    var warning = data.asset_version
                        ? 'Release package version does not match the release tag'
                        : 'No release package is available for this device target';
                    latest.textContent = 'v' + data.latest + ' (' +
                        (window.HARBOR_T ? window.HARBOR_T(warning) : warning) +
                        (data.asset_version ? ': v' + data.asset_version : ': ' + (data.target || '')) +
                        from_mirror + ')';
                    return;
                }
                if (data.latest) {
                    latest.textContent = 'v' + data.latest;
                }
                if (data.has_update) {
                    latest.textContent = 'v' + data.latest + ' (' + HF.labels.update_available + from_mirror + ')';
                    btn.style.display = '';
                }
                else if (data.latest) {
                    latest.textContent = 'v' + data.latest + ' (' + HF.labels.up_to_date + from_mirror + ')';
                }
                else {
                    latest.textContent = HF.labels.update_check_failed;
                }
            },
            error: function() {
                check.disabled = false;
                if (epoch !== HF.state.update_epoch) {
                    return;
                }
                latest.textContent = HF.labels.update_check_failed;
            }
        });
    };

    var UPDATE_TASK_STORAGE_KEY = 'harbor-core-update-task';

    function save_update_task_id(taskId) {
        try { window.localStorage.setItem(UPDATE_TASK_STORAGE_KEY, taskId); } catch (_) {}
    }

    function saved_update_task_id() {
        try {
            var taskId = window.localStorage.getItem(UPDATE_TASK_STORAGE_KEY) || '';
            return /^[A-Za-z0-9_-]{1,64}$/.test(taskId) ? taskId : '';
        } catch (_) { return ''; }
    }

    function clear_saved_update_task_id() {
        try { window.localStorage.removeItem(UPDATE_TASK_STORAGE_KEY); } catch (_) {}
    }

    HF.resume_update_task = function resume_update_task() {
        var taskId = saved_update_task_id();
        if (!taskId || HF.state.update_task_resuming) return;
        HF.state.update_task_resuming = true;
        HF.state.update_poll_failures = 0;
        HF.state.install_item = { name: 'Harbor File Pro', ext: 'repository' };
        HF.update_package_install_view({
            done: false,
            success: false,
            message: HF.labels.installing_update,
            package_type: 'repository',
            installer: 'update'
        });
        HF.set_install_progress(true, 0, HF.labels.installing_update);
        HF.open_modal('fm_package_install_dialog');
        HF.poll_update_status(taskId);
    };

    HF.stop_update_poll = function stop_update_poll() {
        if (HF.state.update_poll_timer) {
            clearTimeout(HF.state.update_poll_timer);
            HF.state.update_poll_timer = null;
        }
    };

    HF.set_install_progress = function set_install_progress(visible, percent, text) {
        var wrap = document.getElementById('fm_install_progress_wrap');
        var bar = document.getElementById('fm_install_progress_bar');
        if (!wrap || !bar) {
            return;
        }
        wrap.style.display = visible ? '' : 'none';
        bar.style.width = Math.max(0, Math.min(100, percent || 0)) + '%';
        if (text !== undefined && text !== null) {
            var status = document.getElementById('fm_package_install_status');
            if (status) {
                status.textContent = text;
            }
        }
    };

    HF.poll_update_status = function poll_update_status(task_id) {
        HF.stop_update_poll();
        HF.Util.ajax({
            url: HF.api.update_status,
            type: 'GET',
            data: { task_id: task_id },
            dataType: 'json',
            success: function(res) {
                HF.state.update_poll_failures = 0;
                if (!res || res.code !== 0) {
                    HF.set_error_status((res && res.message) || HF.labels.request_failed);
                    HF.state.update_poll_timer = setTimeout(function() {
                        HF.poll_update_status(task_id);
                    }, 2000);
                    return;
                }
                var task = res.data || {};
                var done = task.done;
                var phase = task.phase;
                var percent = (task.total > 0)
                    ? (task.downloaded * 100 / task.total)
                    : Math.max(0, Math.min(100, Number(task.progress) || 0));
                var detail = task.total > 0
                    ? ' ' + HF.format_size(task.downloaded || 0) + ' / ' + HF.format_size(task.total)
                    : '';
                var statusText = task.message ||
                    (phase === 'download' || phase === 'main' || phase === 'lang'
                        ? (phase === 'lang' ? HF.labels.downloading_lang : HF.labels.downloading_update)
                        : HF.labels.installing_update);

                if (!done && percent > 0) {
                    HF.set_install_progress(true, percent, statusText + detail);
                } else if (!done) {
                    HF.set_install_progress(false, 0, statusText);
                }

                HF.update_package_install_view({
                    done: done,
                    success: task.success,
                    message: done ? (task.success ? HF.labels.update_finished : (task.message || HF.labels.install_failed))
                                  : statusText + detail,
                    log: task.log,
                    package_type: 'repository',
                    installer: 'update',
                    exit_code: done ? (task.success ? 0 : 1) : undefined
                });
                document.getElementById('fm_package_install_name').textContent = 'Harbor File Pro';
                document.getElementById('fm_package_install_path').textContent =
                    'v-latest (' + (phase || '-') + ')';

                if (!done) {
                    HF.state.update_poll_timer = setTimeout(function() {
                        HF.poll_update_status(task_id);
                    }, 1000);
                    return;
                }
                HF.set_install_progress(false, 0);
                clear_saved_update_task_id();
                HF.state.update_task_resuming = false;
                if (task.success) {
                    HF.set_status(HF.labels.update_finished, 'success');
                }
            },
            error: function() {
                HF.state.update_poll_failures = (HF.state.update_poll_failures || 0) + 1;
                // A changed binary version after restart is not authoritative task status.
                // Keep asking the updater for its persisted result; never infer success.
                if (HF.state.update_poll_failures === 2) {
                    HF.set_status(HF.labels.installing_update, '');
                }
                HF.state.update_poll_timer = setTimeout(function() {
                    HF.poll_update_status(task_id);
                }, 2000);
            }
        });
    };

    HF.start_update = function start_update() {
        var job = HF.state.install_job;
        if (job && (!job.data.done || job.data.state === 'missing')) { HF.show_package_install(job); return; }
        HF.close_modal();
        HF.state.update_poll_failures = 0;
        HF.state.install_item = { name: 'Harbor File Pro', ext: 'repository' };
        HF.update_package_install_view({
            done: false,
            success: false,
            message: HF.labels.downloading_update,
            package_type: 'repository',
            installer: 'update'
        });
        HF.set_install_progress(true, 0, HF.labels.downloading_update);
        HF.open_modal('fm_package_install_dialog');
        HF.request_write(HF.api.update_start, { language: HF.update_language() }, '', function(data) {
            if (data && data.task_id) {
                save_update_task_id(data.task_id);
                HF.state.update_task_resuming = true;
                HF.poll_update_status(data.task_id);
            }
        }, function(message, res) {
            clear_saved_update_task_id();
            HF.state.update_task_resuming = false;
            HF.set_install_progress(false, 0);
            HF.update_package_install_view({
                done: true,
                success: false,
                message: message || HF.labels.install_failed,
                package_type: 'repository',
                installer: 'update'
            });
        }, { quietError: true });
    };

    HF.get_prism_assets = function get_prism_assets() {
        if (!HF.prism_assets_promise) {
            HF.prism_assets_promise = Promise.resolve({ current: HF.asset_version || '1', bundle: 'prism/builtin/prism.js' });
        }
        return HF.prism_assets_promise;
    };
})(window.HarborFile = window.HarborFile || {});
