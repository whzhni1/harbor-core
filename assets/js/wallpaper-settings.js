(function (HF) {
    'use strict';

    var BATCH = 8;
    HF.wallpaper_enabled_dirty = false;

    function by_id(id) { return document.getElementById(id); }
    function tr(text) { return HF.tr ? HF.tr(text) : text; }
    function status(message) { if (HF.set_warning_status && message) HF.set_warning_status(message); }

    HF.wallpaper_state = HF.wallpaper_state || {
        source: 'builtin', type: 'all', page: 1, batch: BATCH,
        items: [], types: [], current: null,
        custom_limit: 8, custom_max_bytes: 5242880
    };

    HF.apply_wallpaper = function apply_wallpaper(current) {
        var root = document.documentElement;
        var values = current || {};
        HF.wallpaper_state.current = values;
        var enabled = values.enabled === true || values.enabled === 1;
        var url = values.url || values.full || '';
        if (!enabled || !url) {
            root.removeAttribute('data-harbor-wallpaper');
            root.style.removeProperty('--fm-wallpaper');
            return;
        }
        root.setAttribute('data-harbor-wallpaper', '');
        root.style.setProperty('--fm-wallpaper', 'url("' + String(url).replace(/"/g, '%22') + '")');
    };

    HF.refresh_wallpaper = function refresh_wallpaper(on_done) {
        if (!HF.api || !HF.api.wallpaper_current) {
            if (on_done) on_done(null);
            return;
        }
        HF.Util.ajax({
            url: HF.api.wallpaper_current,
            type: 'GET',
            data: { _: Date.now() },
            dataType: 'json',
            success: function (res) {
                var current = res && res.code === 0 ? res.data : null;
                if (!current && res && res.message) status(res.message);
                HF.apply_wallpaper(current);
                if (on_done) on_done(current);
            },
            error: function (xhr) {
                var response = HF.response_json ? HF.response_json(xhr) : null;
                status(response && response.message || tr('Cannot refresh wallpaper'));
                if (on_done) on_done(null);
            }
        });
    };

    function type_button(type) {
        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'fm-wallpaper-chip' + (type.id === HF.wallpaper_state.type ? ' active' : '');
        button.setAttribute('role', 'tab');
        button.setAttribute('aria-selected', type.id === HF.wallpaper_state.type ? 'true' : 'false');
        button.textContent = tr(type.label);
        button.addEventListener('click', function () {
            HF.load_wallpaper_page(HF.wallpaper_state.source, type.id, 1);
        });
        return button;
    }

    function render_types() {
        var host = by_id('fm_wallpaper_types');
        if (!host) return;
        HF.clear_node(host);
        (HF.wallpaper_state.types || []).forEach(function (type) {
            host.appendChild(type_button(type));
        });
        host.hidden = !HF.wallpaper_state.types || HF.wallpaper_state.types.length <= 1;
    }

    function tile(item) {
        var card = document.createElement('button');
        card.type = 'button';
        card.className = 'fm-wallpaper-tile';
        card.setAttribute('role', 'listitem');
        card.setAttribute('data-wallpaper-id', item.id);
        if (HF.wallpaper_state.current && HF.wallpaper_state.current.id === item.id) card.classList.add('active');
        card.title = [item.attribution, item.creator_url, item.license_url, item.source_url].filter(Boolean).join('\n') || item.title || item.id;
        var image = document.createElement('img');
        image.loading = 'lazy';
        image.alt = '';
        var triedFull = false;
        image.addEventListener('error', function () {
            if (!triedFull && item.full && item.full !== (item.thumb || item.full)) {
                triedFull = true;
                image.src = item.full;
                return;
            }
            image.hidden = true;
            card.classList.add('fm-wallpaper-unavailable');
            card.title = tr('Request failed') + '\n' + card.title;
        });
        image.src = item.thumb || item.full;
        card.appendChild(image);
        var caption = document.createElement('span');
        caption.className = 'fm-wallpaper-caption';
        var credit = item.creator ? 'by ' + item.creator : '';
        var licenseNames = { cc0: 'CC0', pdm: 'Public Domain', by: 'CC BY', 'by-sa': 'CC BY-SA', 'by-nd': 'CC BY-ND' };
        var license = item.license ? (licenseNames[item.license] || String(item.license).toUpperCase()) : '';
        if (item.license_version) license += ' ' + item.license_version;
        caption.textContent = (item.title || item.id) + (credit || license ? '\n' + [credit, license].filter(Boolean).join(' · ') : '');
        card.appendChild(caption);
        if (HF.wallpaper_state.source === 'custom') {
            var remove = document.createElement('span');
            remove.className = 'fm-wallpaper-delete';
            remove.setAttribute('role', 'button');
            remove.title = tr('Delete');
            remove.textContent = '×';
            remove.addEventListener('click', function (event) {
                event.stopPropagation();
                event.preventDefault();
                delete_custom_wallpaper(item);
            });
            card.appendChild(remove);
        }
        card.addEventListener('click', function () {
            HF.apply_wallpaper_id(item.id, item.source || HF.wallpaper_state.source, item.type || HF.wallpaper_state.type);
        });
        return card;
    }

    function render_grid(items) {
        var host = by_id('fm_wallpaper_grid');
        if (!host) return;
        HF.clear_node(host);
        (items || []).forEach(function (item) { host.appendChild(tile(item)); });
        if (!host.children.length) {
            var empty = document.createElement('div');
            empty.className = 'fm-wallpaper-empty';
            empty.textContent = tr('No wallpapers in this category');
            host.appendChild(empty);
        }
    }

    function sync_custom_actions() {
        var row = by_id('fm_wallpaper_custom_actions');
        if (!row) return;
        var custom = HF.wallpaper_state.source === 'custom';
        row.style.display = custom ? '' : 'none';
        var count = by_id('fm_wallpaper_custom_count');
        if (count) {
            count.textContent = custom
                ? (HF.wallpaper_state.items || []).length + ' / ' + HF.wallpaper_state.custom_limit
                : '';
        }
    }

    function delete_custom_wallpaper(item) {
        var prefix = 'custom:';
        var id = String(item.id || '');
        if (id.indexOf(prefix) !== 0) return;
        var name = id.slice(prefix.length);
        HF.confirm_window({
            title: tr('Confirm delete'),
            message: tr('Are you sure you want to permanently delete this item?')
        }).then(function (confirmed) {
            if (!confirmed) return;
            fetch(HF.api.wallpaper_delete, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
                body: 'name=' + encodeURIComponent(name)
            })
                .then(function (response) {
                    return response.json().catch(function () { return null; });
                })
                .then(function (res) {
                    if (!res || res.code !== 0) {
                        status((res && res.message) || tr('Delete failed'));
                    }
                    HF.load_wallpaper_page('custom', 'all', 1);
                    HF.refresh_wallpaper();
                })
                .catch(function () {
                    status(tr('Delete failed'));
                });
        });
    }

    function upload_wallpaper_files(files) {
        var limit = HF.wallpaper_state.custom_limit || 8;
        var maxBytes = HF.wallpaper_state.custom_max_bytes || 5242880;
        var pending = [];
        for (var index = 0; index < files.length; index++) {
            var file = files[index];
            if (file.size > maxBytes) {
                status(tr('Wallpaper file is too large'));
                return;
            }
            pending.push(file);
        }
        if (!pending.length) return;
        if ((HF.wallpaper_state.items || []).length + pending.length > limit) {
            status(tr('Too many wallpapers'));
            return;
        }
        var form = new FormData();
        pending.forEach(function (file) { form.append('file', file, file.name); });
        fetch(HF.api.wallpaper_upload, {
            method: 'POST',
            credentials: 'same-origin',
            body: form
        })
            .then(function (response) {
                return response.json().catch(function () { return null; });
            })
            .then(function (res) {
                if (!res || res.code !== 0) {
                    status((res && res.message) || tr('Upload failed'));
                } else if (HF.set_status) {
                    HF.set_status(tr('Upload complete'), 'success');
                }
                HF.load_wallpaper_page('custom', 'all', 1);
            })
            .catch(function () {
                status(tr('Upload failed'));
                HF.load_wallpaper_page('custom', 'all', 1);
            });
    }

    HF.sync_wallpaper_custom_actions = sync_custom_actions;
    HF.upload_wallpaper_files = upload_wallpaper_files;

    HF.sync_wallpaper_options = function sync_wallpaper_options() {
        var enabled = !!(by_id('fm_settings_wallpaper_enabled') || {}).checked;
        var options = by_id('fm_wallpaper_settings_options');
        if (options) options.hidden = !enabled;
    };

    function render_current_line() {
        var desc = by_id('fm_wallpaper_current_desc');
        var preview = by_id('fm_wallpaper_preview');
        var current = HF.wallpaper_state.current || {};
        var enabled = current.enabled === true || current.enabled === 1;
        if (desc) desc.textContent = enabled ? tr(current.title || current.id || tr('Wallpaper')) : tr('No wallpaper selected');
        if (preview) {
            preview.style.backgroundImage = enabled && current.thumb
                ? 'url("' + String(current.thumb).replace(/"/g, '%22') + '")'
                : '';
            preview.classList.toggle('is-empty', !(enabled && current.thumb));
            preview.title = '';
            if (enabled && current.thumb) {
                var probe = new Image();
                var probeStage = 0;
                probe.onerror = function () {
                    probeStage += 1;
                    if (probeStage === 1 && current.full) {
                        preview.style.backgroundImage = 'url("' + String(current.full).replace(/"/g, '%22') + '")';
                        probe.src = current.full;
                        return;
                    }
                    preview.style.backgroundImage = '';
                    preview.classList.add('is-empty');
                    preview.title = tr('Request failed');
                };
                probe.src = current.thumb;
            }
        }
        var toggle = by_id('fm_settings_wallpaper_enabled');
        if (toggle && !HF.wallpaper_enabled_dirty) toggle.checked = enabled;
        HF.sync_wallpaper_options();
        var mode = by_id('fm_settings_wallpaper_mode');
        if (mode && current.mode) mode.value = current.mode;
    }

    HF.load_wallpaper_page = function load_wallpaper_page(source, imageType, page, on_done) {
        if (!HF.api || !HF.api.wallpaper_catalog) {
            if (on_done) on_done(null);
            return;
        }
        HF.wallpaper_state.source = source || HF.wallpaper_state.source || 'builtin';
        HF.wallpaper_state.type = imageType || 'all';
        HF.wallpaper_state.page = Math.max(1, Number(page) || 1);
        HF.wallpaper_state.request_id = (HF.wallpaper_state.request_id || 0) + 1;
        var requestId = HF.wallpaper_state.request_id;
        render_types();
        var grid = by_id('fm_wallpaper_grid');
        if (grid) {
            grid.setAttribute('aria-busy', 'true');
            HF.clear_node(grid);
            var loading = document.createElement('div');
            loading.className = 'fm-wallpaper-empty';
            loading.textContent = tr('Loading wallpapers…');
            grid.appendChild(loading);
        }
        HF.Util.ajax({
            url: HF.api.wallpaper_catalog,
            type: 'GET',
            data: {
                source: HF.wallpaper_state.source,
                type: HF.wallpaper_state.type,
                page: HF.wallpaper_state.page,
                count: HF.wallpaper_state.batch || BATCH,
                _: Date.now()
            },
            dataType: 'json',
            success: function (res) {
                if (requestId !== HF.wallpaper_state.request_id) return;
                var data = res && res.code === 0 ? res.data : null;
                if (!data) {
                    if (grid) {
                        grid.setAttribute('aria-busy', 'false');
                        var failed = grid.firstElementChild;
                        if (failed) failed.textContent = tr('Cannot load the wallpaper gallery');
                    }
                    status(res && res.message || tr('Cannot load the wallpaper gallery'));
                    if (on_done) on_done(null);
                    return;
                }
                if (grid) grid.setAttribute('aria-busy', 'false');
                HF.wallpaper_state.items = data.items || [];
                HF.wallpaper_state.types = data.types || [];
                HF.wallpaper_state.next_page = data.next_page || 1;
                HF.wallpaper_state.total = data.total || 0;
                if (data.current) HF.wallpaper_state.current = data.current;
                var sourceSelect = by_id('fm_settings_wallpaper_source');
                if (sourceSelect) sourceSelect.value = HF.wallpaper_state.source;
                var nextButton = by_id('fm_settings_wallpaper_next');
                if (nextButton) {
                    nextButton.hidden = HF.wallpaper_state.source === 'custom';
                    nextButton.disabled = data.has_more === false;
                }
                if (data.custom_limit) HF.wallpaper_state.custom_limit = data.custom_limit;
                if (data.custom_max_bytes) HF.wallpaper_state.custom_max_bytes = data.custom_max_bytes;
                sync_custom_actions();
                render_types();
                render_grid(HF.wallpaper_state.items);
                render_current_line();
                if (on_done) on_done(data);
            },
            error: function (xhr) {
                if (requestId !== HF.wallpaper_state.request_id) return;
                if (grid) {
                    grid.setAttribute('aria-busy', 'false');
                    var failed = grid.firstElementChild;
                    if (failed) failed.textContent = tr('Cannot load the wallpaper gallery');
                }
                var response = HF.response_json ? HF.response_json(xhr) : null;
                status(response && response.message || tr('Cannot load the wallpaper gallery'));
                if (on_done) on_done(null);
            }
        });
    };

    HF.wallpaper_next_batch = function wallpaper_next_batch() {
        HF.load_wallpaper_page(HF.wallpaper_state.source, HF.wallpaper_state.type,
            HF.wallpaper_state.next_page || HF.wallpaper_state.page + 1);
    };

    HF.apply_wallpaper_id = function apply_wallpaper_id(id, source, imageType) {
        if (!id) return;
        var modeControl = by_id('fm_settings_wallpaper_mode');
        if (modeControl) modeControl.value = 'fixed';
        HF.Util.ajax({
            url: HF.api.wallpaper_apply,
            type: 'POST',
            data: { id: id, source: source || HF.wallpaper_state.source, type: imageType || HF.wallpaper_state.type, mode: 'fixed' },
            dataType: 'json',
            success: function (res) {
                if (res && res.code === 0) {
                    HF.apply_wallpaper(res.data);
                    HF.load_wallpaper_page(HF.wallpaper_state.source, HF.wallpaper_state.type, HF.wallpaper_state.page);
                } else {
                    status(res && res.message || tr('Cannot apply the wallpaper'));
                }
            },
            error: function (xhr) {
                var response = HF.response_json ? HF.response_json(xhr) : null;
                status(response && response.message || tr('Cannot apply the wallpaper'));
            }
        });
    };

    HF.remove_wallpaper = function remove_wallpaper() {
        HF.Util.ajax({
            url: HF.api.wallpaper_remove,
            type: 'POST',
            data: { _: Date.now() },
            dataType: 'json',
            success: function (res) {
                if (res && res.code === 0) {
                    HF.apply_wallpaper(res.data);
                    render_current_line();
                    HF.load_wallpaper_page(HF.wallpaper_state.source, HF.wallpaper_state.type, HF.wallpaper_state.page);
                } else status(res && res.message || tr('Cannot remove the wallpaper'));
            },
            error: function () { status(tr('Cannot remove the wallpaper')); }
        });
    };

    HF.save_theme_settings = function save_theme_settings() {
        var theme = (by_id('fm_settings_theme') || {}).value || 'auto';
        var enabled = by_id('fm_settings_wallpaper_enabled').checked;
        function save_wallpaper() {
            HF.save_preferences({
                section: 'wallpaper',
                enabled: enabled ? 1 : 0,
                login_enabled: by_id('fm_settings_wallpaper_login').checked ? 1 : 0,
                mode: (by_id('fm_settings_wallpaper_mode') || {}).value || 'fixed',
                id: (HF.wallpaper_state.current && HF.wallpaper_state.current.id) || 'builtin:img2',
                source: (by_id('fm_settings_wallpaper_source') || {}).value || HF.wallpaper_state.source || 'builtin',
                type: HF.wallpaper_state.type || 'all'
            }, HF.labels.settings_saved, function () {
                HF.wallpaper_enabled_dirty = false;
                render_current_line();
            });
        }
        HF.save_preferences({ section: 'appearance', theme: theme }, '', save_wallpaper, function (message) {
            if (HF.set_error_status) HF.set_error_status(message || tr('Cannot save settings'));
        });
    };

    HF.render_theme_settings = function render_theme_settings() {
        var theme = by_id('fm_settings_theme');
        if (theme) theme.value = HF.state.preferences.theme || 'auto';
        var prefs = HF.state.preferences || {};
        HF.wallpaper_enabled_dirty = false;
        var enabledToggle = by_id('fm_settings_wallpaper_enabled');
        if (enabledToggle) enabledToggle.checked = prefs.wallpaper_enabled === 1;
        HF.sync_wallpaper_options();
        var loginToggle = by_id('fm_settings_wallpaper_login');
        if (loginToggle) loginToggle.checked = prefs.wallpaper_login_enabled === 1;
        HF.wallpaper_state.source = prefs.wallpaper_source || 'builtin';
        HF.wallpaper_state.type = prefs.wallpaper_type || 'all';
        HF.load_wallpaper_page(HF.wallpaper_state.source, HF.wallpaper_state.type, 1);
    };
})(window.HarborFile);

(function (HF) {
    'use strict';
    function on(id, event, handler) {
        var node = document.getElementById(id);
        if (node) node.addEventListener(event, handler);
    }
    HF.bind_theme_settings = function bind_theme_settings() {
        on('fm_settings_theme_save', 'click', function () { HF.save_theme_settings(); });
        on('fm_settings_theme_cancel', 'click', function () { HF.close_modal(); });
        on('fm_settings_wallpaper_next', 'click', function () { HF.wallpaper_next_batch(); });
        on('fm_settings_wallpaper_remove', 'click', function () { HF.remove_wallpaper(); });
        on('fm_settings_wallpaper_upload', 'click', function () {
            var input = document.getElementById('fm_wallpaper_upload_input');
            if (input) input.click();
        });
        on('fm_wallpaper_upload_input', 'change', function () {
            if (this.files && this.files.length && HF.upload_wallpaper_files) HF.upload_wallpaper_files(this.files);
            this.value = '';
        });
        on('fm_settings_wallpaper_source', 'change', function () {
            HF.load_wallpaper_page(this.value || 'builtin', 'all', 1);
        });
        if (HF.sync_wallpaper_custom_actions) HF.sync_wallpaper_custom_actions();
        on('fm_settings_wallpaper_enabled', 'change', function () {
            HF.wallpaper_enabled_dirty = true;
            HF.sync_wallpaper_options();
        });
    };
})(window.HarborFile);
