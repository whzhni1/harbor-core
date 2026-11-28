/* Runtime localisation for the static web client.
 * The authoritative catalog is fetched from /api/v1/i18n; no translation table
 * is bundled with the frontend. The chosen language is stored locally and sent
 * as a cookie so the backend localises its own response messages too.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'harbor.lang';
    var COOKIE = 'harbor_lang';
    var table = {};
    var active = false;

    function readStored() {
        var stored = '';
        try { stored = window.localStorage.getItem(STORAGE_KEY) || ''; } catch (e) { }
        return stored === 'auto' ? '' : stored;
    }

    function readPreference() {
        var stored = readStored();
        if (stored) return stored;
        var navigatorLang = (navigator.languages && navigator.languages[0]) || navigator.language || '';
        return navigatorLang || 'en';
    }

    function remember(lang) {
        try { window.localStorage.setItem(STORAGE_KEY, lang); } catch (e) { }
        rememberCookie(lang);
    }

    function rememberCookie(lang) {
        document.cookie = COOKIE + '=' + encodeURIComponent(lang) + '; path=/; max-age=31536000; SameSite=Lax';
    }

    function normalize(tag) {
        return String(tag || '').replace(/-/g, '_');
    }

    function lookup(text) {
        if (!text || !active) return null;
        var key = text.trim();
        if (!key) return null;
        return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : null;
    }

    function translateLabels() {
        var config = window.HARBOR_CONFIG;
        if (!config || !config.labels) return;
        for (var key in config.labels) {
            if (!Object.prototype.hasOwnProperty.call(config.labels, key)) continue;
            var value = lookup(config.labels[key]);
            if (value) config.labels[key] = value;
        }
    }

    function translateNode(root) {
        var attributes = ['title', 'placeholder', 'aria-label', 'alt'];
        var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, null);
        var node = walker.currentNode;
        var pending = [];
        while (node) {
            if (node.nodeType === 3) {
                var value = lookup(node.nodeValue);
                if (value) pending.push([node, value]);
            } else if (node.nodeType === 1) {
                for (var i = 0; i < attributes.length; i++) {
                    var attr = attributes[i];
                    if (node.hasAttribute && node.hasAttribute(attr)) {
                        var translated = lookup(node.getAttribute(attr));
                        if (translated) node.setAttribute(attr, translated);
                    }
                }
                if (node.tagName === 'OPTION' && node.textContent) {
                    var optionValue = lookup(node.textContent);
                    if (optionValue && node.firstChild) pending.push([node.firstChild, optionValue]);
                }
            }
            node = walker.nextNode();
        }
        for (var k = 0; k < pending.length; k++) {
            if (pending[k][0]) pending[k][0].nodeValue = pending[k][1];
        }
    }

    function translateDocument() {
        translateLabels();
        if (document.body) translateNode(document.body);
    }

    function watch() {
        if (!document.body || typeof MutationObserver === 'undefined') return;
        var observer = new MutationObserver(function (records) {
            for (var i = 0; i < records.length; i++) {
                var added = records[i].addedNodes;
                for (var j = 0; j < added.length; j++) {
                    if (added[j].nodeType === 1) translateNode(added[j]);
                }
            }
        });
        observer.observe(document.body, { childList: true, subtree: true });
    }

     
    window.HARBOR_T = function (text) {
        return lookup(text) || text;
    };

     
    window.harborSetLanguage = function (lang) {
        remember(normalize(lang));
        window.location.reload();
    };

    window.HARBOR_LANG_CONFIGURED = '';

    window.harborLanguageChoice = function () {
        var stored = readStored();
        if (stored) return normalize(stored);
        if (window.HARBOR_LANG_CONFIGURED) return normalize(window.HARBOR_LANG_CONFIGURED);
        return 'auto';
    };

    function applyCatalog(tag) {
        return fetch('/api/v1/i18n?lang=' + encodeURIComponent(tag), { credentials: 'same-origin' })
            .then(function (response) { return response.ok ? response.json() : null; })
            .then(function (payload) {
                var data = payload && payload.data;
                if (!data) return false;
                wanted = tag;
                window.HARBOR_LANGS = data.languages || [];
                window.HARBOR_LANG = data.lang || tag;
                window.HARBOR_LANG_CONFIGURED = data.configured ? normalize(data.configured) : '';
                if (data.messages && Object.keys(data.messages).length) {
                    table = data.messages;
                    active = true;
                } else {
                    table = {};
                    active = false;
                }
                try { document.documentElement.lang = window.HARBOR_LANG; } catch (e) { }
                translateDocument();
                try {
                    document.dispatchEvent(new CustomEvent('harbor:i18n', { detail: { lang: window.HARBOR_LANG } }));
                } catch (e) { }
                return true;
            })
            .catch(function () { return false; });
    }

    window.harborApplyLanguage = function (lang) {
        var tag = normalize(lang);
        remember(tag);
        return applyCatalog(tag);
    };

    window.harborAutoLanguage = function () {
        try { window.localStorage.removeItem(STORAGE_KEY); } catch (e) { }
        var nav = normalize((navigator.languages && navigator.languages[0]) || navigator.language || 'en');
        rememberCookie(nav);
        return applyCatalog(nav);
    };

    var rawStored = readStored();
    var wanted = normalize(readPreference());
    rememberCookie(wanted);

    function start() {
        translateDocument();
        watch();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }

    function applyPayload(data) {
        if (!data) return;
        window.HARBOR_LANGS = data.languages || [];
        window.HARBOR_LANG = data.lang || wanted;
        window.HARBOR_LANG_CONFIGURED = data.configured ? normalize(data.configured) : '';
        if (data.messages && Object.keys(data.messages).length) {
            table = data.messages;
            active = true;
        }
        try { document.documentElement.lang = data.lang || wanted; } catch (e) { }
        translateDocument();
        try {
            document.dispatchEvent(new CustomEvent('harbor:i18n', { detail: { lang: data.lang } }));
        } catch (e) { }
    }

    function loadCatalog(langTag) {
        if (typeof fetch !== 'function') return;
        fetch('/api/v1/i18n?lang=' + encodeURIComponent(langTag), { credentials: 'same-origin' })
            .then(function (response) { return response.ok ? response.json() : null; })
            .then(function (payload) {
                var data = payload && payload.data;
                if (!data) return;
                var configured = data.configured ? normalize(data.configured) : '';
                if (configured && !rawStored && configured !== normalize(langTag)) {
                    wanted = configured;
                    rememberCookie(configured);
                    loadCatalog(configured);
                    return;
                }
                if (data.lang) rememberCookie(normalize(data.lang));
                applyPayload(data);
            })
            .catch(function () { });
    }
    loadCatalog(wanted);
})();
