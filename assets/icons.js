
(function () {
    'use strict';

    var manifest = window.HARBOR_ICONS || { icons: {}, fallback: 'file', sprite: 'inline' };
    var icons = manifest.icons || {};
    var fallback = manifest.fallback || 'file';
    var warned = Object.create(null);

    function normalize(name) {
        if (!name) return '';
        var value = String(name).trim();
        var slash = value.lastIndexOf('/');
        if (slash >= 0) value = value.slice(slash + 1);
        if (/\.svg$/i.test(value)) value = value.slice(0, -4);
        return value.toLowerCase();
    }

    function known(key) {
        return Object.prototype.hasOwnProperty.call(icons, key);
    }

    function resolve(name) {
        var key = normalize(name) || fallback;
        if (known(key)) return key;
        if (!warned[key]) {
            warned[key] = true;
            if (window.console && console.warn) {
                console.warn('harbor: unknown icon key "' + key + '", using "' + fallback + '"');
            }
        }
        return fallback;
    }

    
    
    function url(name) {
        return icons[resolve(name)] || icons[fallback] || 'none';
    }

    
    
    function symbol_id(name) {
        return '#hf-' + resolve(name);
    }

    function make(name, className) {
        var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('class', className || 'hf-icon');
        svg.setAttribute('aria-hidden', 'true');
        svg.setAttribute('focusable', 'false');
        var viewBox = (manifest.viewbox || {})[resolve(name)];
        if (viewBox) svg.setAttribute('viewBox', viewBox);
        var use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
        use.setAttribute('href', symbol_id(name));
        use.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', symbol_id(name));
        svg.appendChild(use);
        return svg;
    }

    
    function hydrate(root) {
        if (!root || !root.querySelectorAll) return;
        var nodes = root.querySelectorAll('[data-icon]');
        for (var i = 0; i < nodes.length; i++) {
            var node = nodes[i];
            if (node.getAttribute('data-icon-ready') === '1') continue;
            node.setAttribute('data-icon-ready', '1');
            node.insertBefore(make(node.getAttribute('data-icon'), node.getAttribute('data-icon-class')), node.firstChild);
        }
    }

    window.HARBOR_ICON_URL = url;
    window.HARBOR_ICON = make;
    window.HARBOR_ICONS_REGISTRY = {
        has: function (name) { return known(normalize(name)); },
        list: function () { return Object.keys(icons); },
        url: url,
        make: make,
        fallback: fallback
    };

    
    function app() { return window.HarborFile || window.HF; }

    function attach(attempt) {
        var HF = app();
        if (!HF) {
            
            
            if ((attempt || 0) < 100) setTimeout(function () { attach((attempt || 0) + 1); }, 30);
            return;
        }
        
        
        HF.icon_url = url;
        HF.icon = make;
        HF.icons = window.HARBOR_ICONS_REGISTRY;
        if (HF.Util) {
            HF.Util.icon_url = url;
            HF.Util.icon = make;
        }
        hydrate(document.body);
        if (typeof MutationObserver !== 'undefined' && document.body) {
            new MutationObserver(function (records) {
                for (var i = 0; i < records.length; i++) {
                    var added = records[i].addedNodes;
                    for (var j = 0; j < added.length; j++) {
                        if (added[j].nodeType === 1) hydrate(added[j]);
                    }
                }
            }).observe(document.body, { childList: true, subtree: true });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attach);
    } else {
        attach();
    }
})();
