(function () {
    'use strict';

    window.addEventListener('pageshow', function (event) {
        if (event.persisted) window.location.reload();
    });

    var ROW_LIMIT = 12;
    var pingMs = 30000;
    var rxLimitMs = 75000;

    var query = new URLSearchParams(window.location.search);
    var sessionId = query.get('session') || '';
    if (!sessionId) {
        sessionId = 'term-xxxxxxxxxxxx'.replace(/x/g, function () {
            return Math.random().toString(36).slice(2, 10);
        }).slice(0, 24);
    }
    var deviceId = query.get('device') || '';
    var startPath = query.get('path') || '';

    var container = document.getElementById('term_container');
    var menu = document.getElementById('term_menu');
    var banner = document.getElementById('term_banner');
    var bannerText = document.getElementById('term_banner_text');
    var bannerAction = document.getElementById('term_banner_action');

    var term = new Terminal({
        fontSize: 14,
        cursorBlink: true,
        scrollback: 10000,
        fontFamily: 'Menlo, Monaco, "Cascadia Mono", "Segoe Mono", Consolas, "Liberation Mono", monospace',
        theme: { background: '#05070a', foreground: '#d8dee9' }
    });
    var fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);

    var ws = null;
    var pendingInput = '';
    var manualClose = false;
    var exitShown = false;
    var retryCount = 0;
    var lastRx = Date.now();
    var lastPing = Date.now();
    var reconnectTimer = null;
    var encoder = new TextEncoder();

    fetch('/api/v1/preferences', { credentials: 'same-origin' }).then(function(response) {
        return response.ok ? response.json() : null;
    }).then(function(payload) {
        var data = payload && payload.data;
        if (data && Number(data.terminal_ping) >= 5) {
            pingMs = Math.min(600, Number(data.terminal_ping)) * 1000;
            rxLimitMs = Math.max(20000, pingMs * 2.5);
        }
    }).catch(function() { });

    function fitNow() {
        try { fitAddon.fit(); } catch (e) { }
        try { syncViewport(); } catch (e) { }
        updateHandles();
    }
    fitNow();
    if (window.requestAnimationFrame) {
        requestAnimationFrame(function () { requestAnimationFrame(fitNow); });
    }
    if (document.fonts && document.fonts.ready && document.fonts.ready.then) {
        document.fonts.ready.then(function () { fitNow(); });
    }
    if (window.ResizeObserver) {
        new ResizeObserver(function () { fitNow(); }).observe(container);
    } else {
        window.addEventListener('resize', fitNow);
    }

    function sendControl(payload) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(payload));
        }
    }

    function sendInput(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(typeof data === 'string' ? encoder.encode(data) : data);
        } else if (typeof data === 'string') {
            if (pendingInput.length > 512) pendingInput = pendingInput.slice(-512);
            pendingInput += data;
        }
    }

    function wsUrl() {
        var parts = ['session=' + encodeURIComponent(sessionId), 'cols=' + term.cols, 'rows=' + term.rows];
        if (deviceId) parts.push('device=' + encodeURIComponent(deviceId));
        if (startPath) parts.push('path=' + encodeURIComponent(startPath));
        var proto = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
        return proto + window.location.host + '/api/v1/terminal/ws?' + parts.join('&');
    }

    function showBanner(text, withAction) {
        bannerText.textContent = text;
        bannerAction.hidden = !withAction;
        banner.classList.add('show');
    }

    function hideBanner() {
        banner.classList.remove('show');
    }

    function scheduleReconnect() {
        if (manualClose || exitShown || reconnectTimer) return;
        showBanner('Connection lost, reconnecting…', false);
        var delay = Math.min(5000, 400 * Math.pow(2, retryCount));
        retryCount += 1;
        reconnectTimer = setTimeout(function () {
            reconnectTimer = null;
            connect();
        }, delay);
    }

    function connect() {
        if (manualClose) return;
        var socket = new WebSocket(wsUrl());
        socket.binaryType = 'arraybuffer';
        ws = socket;
        socket.onopen = function () {
            if (ws !== socket) return;
            retryCount = 0;
            lastRx = Date.now();
            sendControl({ type: 'resize', cols: term.cols, rows: term.rows });
            if (pendingInput) {
                var queued = pendingInput;
                pendingInput = '';
                socket.send(encoder.encode(queued));
            }
            if (window.matchMedia && window.matchMedia('(pointer: fine)').matches) focusTerminal();
            if (!exitShown) hideBanner();
        };
        socket.onmessage = function (event) {
            if (ws !== socket) return;
            lastRx = Date.now();
            if (typeof event.data === 'string') {
                var payload = null;
                try { payload = JSON.parse(event.data); } catch (e) { }
                if (payload && payload.type === 'exit') {
                    exitShown = true;
                    showBanner('Session ended', true);
                }
                return;
            }
            if (event.data && event.data.byteLength) {
                term.write(new Uint8Array(event.data));
            }
        };
        socket.onclose = function () {
            if (ws !== socket) return;
            ws = null;
            if (manualClose) return;
            if (exitShown) {
                showBanner('Session ended', true);
                return;
            }
            scheduleReconnect();
        };
        socket.onerror = function () {
            if (ws === socket) {
                try { socket.close(); } catch (e) { }
            }
        };
    }

    bannerAction.addEventListener('click', function () {
        exitShown = false;
        retryCount = 0;
        hideBanner();
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
        connect();
    });

    setInterval(function () {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        var now = Date.now();
        if (now - lastRx > rxLimitMs) {
            try { ws.close(); } catch (e) { }
            return;
        }
        if (now - lastPing >= pingMs) {
            lastPing = now;
            sendControl({ type: 'ping' });
        }
    }, 1000);

    window.addEventListener('beforeunload', function () {
        manualClose = true;
        if (reconnectTimer) clearTimeout(reconnectTimer);
        if (ws) {
            try { ws.close(); } catch (e) { }
        }
    });

    document.addEventListener('visibilitychange', function () {
        if (document.hidden) {
            onTouchCancel();
            if (menuOpen) hideMenu();
            if (handleDrag) {
                handleDrag.ended = false;
                endHandleDrag();
            }
            updateHandles();
        }
        if (!document.hidden && !ws && !manualClose && !reconnectTimer && !exitShown) {
            connect();
        }
    });

    term.onData(function (data) {
        if (modState.ctrl || modState.alt) {
            if (data.length === 1) {
                if (modState.ctrl && modState.alt) data = '\x1b' + ctrlTransform(data);
                else if (modState.ctrl) data = ctrlTransform(data);
                else if (modState.alt) data = '\x1b' + data;
            }
            resetMods();
        }
        sendInput(data);
    });
    term.onResize(function (size) {
        sendControl({ type: 'resize', cols: size.cols, rows: size.rows });
    });
    term.onTitleChange(function (title) {
        document.title = title || 'Terminal';
    });

    var root = term.element;
    var shield = document.createElement('div');
    shield.className = 'term_shield';
    root.appendChild(shield);
    var menuOpen = false;
    var touchState = null;
    var suppressClickUntil = 0;
    var clipboardKnown = false;
    var flingRaf = 0;
    var scrollAcc = 0;
    var selAnchor = null;
    var selHead = null;
    var handleDrag = null;
    var handleStart = document.getElementById('term_handle_start');
    var handleEnd = document.getElementById('term_handle_end');
    var pointerFine = window.matchMedia && window.matchMedia('(pointer: fine)').matches;

    function getScreen() {
        return root ? root.querySelector('.xterm-screen') : null;
    }

    function getTextArea() {
        return root ? root.querySelector('textarea.xterm-helper-textarea') : null;
    }

    function screenRect() {
        var el = getScreen();
        return el ? el.getBoundingClientRect() : null;
    }

    function cellOf(clientX, clientY) {
        var rect = screenRect();
        if (!rect || rect.width <= 0 || rect.height <= 0 || term.cols <= 0 || term.rows <= 0) return null;
        var relX = clientX - rect.left;
        var relY = clientY - rect.top;
        if (relX < 0 || relX >= rect.width || relY < 0 || relY >= rect.height) return null;
        var col = Math.floor(relX / (rect.width / term.cols));
        var row = Math.floor(relY / (rect.height / term.rows));
        if (col < 0) col = 0;
        if (col >= term.cols) col = term.cols - 1;
        if (row < 0) row = 0;
        if (row >= term.rows) row = term.rows - 1;
        var buf = term.buffer.active;
        var baseY = buf.viewportY;
        if (baseY === undefined || baseY === null) baseY = term.buffer.baseY;
        return { col: col, row: row, bufferY: baseY + row };
    }

    function cellFromChar(y, x) {
        return (y * term.cols) + x;
    }

    function applySelection(anchor, head) {
        selAnchor = anchor;
        selHead = head;
        try { term.clearSelection(); } catch (e) { }
        try {
            var start = Math.min(anchor.bufferY * term.cols + anchor.col, head.bufferY * term.cols + head.col);
            var end = Math.max(anchor.bufferY * term.cols + anchor.col, head.bufferY * term.cols + head.col);
            term.select(start % term.cols, Math.floor(start / term.cols), end - start + 1);
        } catch (e) { }
        updateHandles();
    }

    function copyText(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text).then(function () { clipboardKnown = true; return true; });
        }
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
        document.body.removeChild(ta);
        if (ok) clipboardKnown = true;
        focusTerminal();
        return Promise.resolve(ok);
    }

    function doCopy() {
        var text = term.getSelection();
        if (text) copyText(text).catch(function () { });
    }

    function doSelectAll() {
        selAnchor = null;
        selHead = null;
        try { term.selectAll(); } catch (e) { }
        if (menuOpen) updateMenuStates();
    }

    function doPaste() {
        if (navigator.clipboard && navigator.clipboard.readText) {
            navigator.clipboard.readText().then(function (text) {
                if (text) term.paste(text);
                else focusTerminal();
            }).catch(function () {
                focusTerminal();
            });
        } else {
            focusTerminal();
        }
    }

    function focusTerminal() {
        try {
            var ta = getTextArea();
            if (ta && document.activeElement === ta) ta.blur();
            term.focus();
        } catch (e) { }
    }

    function updateMenuStates() {
        var copyButton = menu.querySelector('[data-action="copy"]');
        var pasteButton = menu.querySelector('[data-action="paste"]');
        if (copyButton) copyButton.disabled = !term.hasSelection();
        if (pasteButton) {
            if (navigator.clipboard && navigator.clipboard.readText) {
                pasteButton.disabled = true;
                var settled = false;
                var timer = setTimeout(function () {
                    if (settled) return;
                    settled = true;
                    if (menuOpen) pasteButton.disabled = false;
                }, 400);
                navigator.clipboard.readText().then(function (text) {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timer);
                    if (menuOpen) pasteButton.disabled = !text;
                }).catch(function () {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timer);
                    if (menuOpen) pasteButton.disabled = false;
                });
            } else {
                pasteButton.disabled = false;
            }
        }
    }

    function clearNativeSelection() {
        try {
            var sel = window.getSelection();
            if (sel && sel.rangeCount) sel.removeAllRanges();
        } catch (e) { }
    }

    function showMenu(x, y) {
        menuOpen = true;
        clearNativeSelection();
        menu.style.display = 'flex';
        menu.style.left = '';
        menu.style.top = '';
        menu.style.bottom = '';
        if (typeof x === 'number' && typeof y === 'number') {
            var menuWidth = menu.offsetWidth;
            var menuHeight = menu.offsetHeight;
            var center = Math.min(Math.max(menuWidth / 2 + 6, x), window.innerWidth - menuWidth / 2 - 6);
            var top;
            if (window.matchMedia && window.matchMedia('(pointer: fine)').matches) {
                top = y + 8;
                if (top + menuHeight > window.innerHeight - 6) top = Math.max(6, y - menuHeight - 14);
            } else {
                top = y - menuHeight - 14;
                if (top < 6) top = Math.min(y + 18, window.innerHeight - menuHeight - 6);
            }
            menu.style.left = center + 'px';
            menu.style.top = top + 'px';
            menu.style.bottom = 'auto';
        }
        updateMenuStates();
    }

    function hideMenu(silent) {
        menuOpen = false;
        menu.style.display = 'none';
        if (!silent && term.hasSelection()) doCopy();
    }

    function onMenuAction(action) {
        if (action === 'selectAll') {
            doSelectAll();
            return;
        }
        if (action === 'copy') {
            doCopy();
            hideMenu(true);
            focusTerminal();
            return;
        }
        if (action === 'paste') {
            doPaste();
            hideMenu(true);
            focusTerminal();
            return;
        }
        hideMenu();
        focusTerminal();
    }

    Array.prototype.forEach.call(menu.querySelectorAll('button[data-action]'), function (button) {
        button.addEventListener('click', function (event) {
            event.preventDefault();
            event.stopPropagation();
            onMenuAction(button.getAttribute('data-action'));
        });
    });

    function sendPointer(data, col, row) {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        var buffer = new Uint8Array(data.length + 3);
        buffer.set(data, 0);
        buffer[data.length] = col + 32;
        buffer[data.length + 1] = row + 32;
        buffer[data.length + 2] = 32;
        ws.send(buffer);
    }

    function sendTap(col, row) {
        sendPointer(new Uint8Array([0x1b, 0x5b, 0x4d]), col, row);
        setTimeout(function () {
            sendPointer(new Uint8Array([0x1b, 0x5b, 0x6d]), col, row);
        }, 50);
    }

    function isFinePointer() {
        return !!(window.matchMedia && window.matchMedia('(pointer: fine)').matches);
    }

    function wantBrowserMenu(event) {
        return !!event.shiftKey || (!window.isSecureContext && isFinePointer());
    }

    function syncNativeSelection() {
        if (!term || !term.hasSelection()) return;
        var text = term.getSelection();
        var ta = root && root.querySelector('.xterm-helper-textarea');
        if (!text || !ta) return;
        ta.value = text;
        ta.setSelectionRange(0, text.length);
    }

    function onContextMenu(event) {
        if (wantBrowserMenu(event)) {
            syncNativeSelection();
            return;
        }
        if (!root || !root.contains(event.target)) return;
        event.preventDefault();
        event.stopPropagation();
        showMenu(event.clientX, event.clientY);
    }

    function onMouseDown(event) {
        if (!root || !root.contains(event.target)) return;
        if (event.button === 0) {
            var clearTa = root.querySelector('.xterm-helper-textarea');
            if (clearTa && clearTa.value) clearTa.value = '';
        }
        if (event.sourceCapabilities && event.sourceCapabilities.firesTouchEvents) {
            event.preventDefault();
            event.stopPropagation();
            return;
        }
        if (Date.now() < suppressClickUntil) {
            event.preventDefault();
            event.stopPropagation();
            return;
        }
        if (event.button === 2) {
            event.stopPropagation();
            return;
        }
        if (menuOpen && !menu.contains(event.target)) {
            hideMenu();
        }
        if (event.detail > 1) {
            event.preventDefault();
            event.stopPropagation();
            return;
        }
        if (menuOpen && menu.contains(event.target)) {
            event.preventDefault();
            event.stopPropagation();
        }
    }

    function cellHeight() {
        var rect = screenRect();
        if (!rect || rect.height <= 0 || term.rows <= 0) return 16;
        return rect.height / term.rows;
    }

    function scrollByLines(amount) {
        scrollAcc += amount;
        var whole = Math.trunc(scrollAcc);
        if (whole === 0) return;
        scrollAcc -= whole;
        try { term.scrollLines(whole); } catch (e) { }
    }

    function stopFling() {
        if (flingRaf) {
            cancelAnimationFrame(flingRaf);
            flingRaf = 0;
        }
    }

    function startFling(velocity) {
        if (Math.abs(velocity) < 0.03) { updateHandles(); return; }
        var last = performance.now();
        function step(now) {
            var dt = Math.min(48, now - last);
            last = now;
            velocity *= Math.pow(0.92, dt / 16.7);
            scrollByLines(velocity * dt / 16.7);
            if (Math.abs(velocity) > 0.03 && !touchState) {
                flingRaf = requestAnimationFrame(step);
            } else {
                flingRaf = 0;
                updateHandles();
            }
        }
        flingRaf = requestAnimationFrame(step);
    }

    function wordSelectAt(cell) {
        try {
            var line = term.buffer.active.getLine(cell.bufferY);
            var text = line ? line.translateToString(true) : '';
            var c1 = 0;
            var c2 = Math.max(0, Math.min(term.cols, text.length) - 1);
            if (text.length) {
                var c = Math.min(cell.col, text.length - 1);
                if (/\S/.test(text.charAt(c))) {
                    c1 = c;
                    c2 = c;
                    while (c1 > 0 && /\S/.test(text.charAt(c1 - 1))) c1--;
                    while (c2 < text.length - 1 && /\S/.test(text.charAt(c2 + 1))) c2++;
                } else {
                    var runL = c;
                    var runR = c;
                    while (runL > 0 && !/\S/.test(text.charAt(runL - 1))) runL--;
                    while (runR < text.length - 1 && !/\S/.test(text.charAt(runR + 1))) runR++;
                    c1 = runL;
                    c2 = runR;
                    if (runR + 1 < text.length && /\S/.test(text.charAt(runR + 1))) {
                        while (c2 < text.length - 1 && /\S/.test(text.charAt(c2 + 1))) c2++;
                    } else if (runL > 0 && /\S/.test(text.charAt(runL - 1))) {
                        while (c1 > 0 && /\S/.test(text.charAt(c1 - 1))) c1--;
                    }
                }
            }
            applySelection({ col: c1, bufferY: cell.bufferY }, { col: c2, bufferY: cell.bufferY });
            clearNativeSelection();
            if (touchState) touchState.anchor = { col: c1, bufferY: cell.bufferY };
        } catch (e) { }
    }

    function viewportRowOf(bufferY) {
        var buf = term.buffer.active;
        var vy = buf.viewportY;
        if (vy === undefined || vy === null) vy = buf.baseY;
        var row = bufferY - vy;
        if (row < 0) row = 0;
        if (row >= term.rows) row = term.rows - 1;
        return row;
    }

    function hideHandles() {
        if (handleStart) handleStart.classList.remove('on');
        if (handleEnd) handleEnd.classList.remove('on');
    }

    function positionHandle(el, x, y) {
        if (!el) return;
        el.style.left = x + 'px';
        el.style.top = y + 'px';
        el.classList.add('on');
    }

    function updateHandles() {
        var show = !!(selAnchor && selHead && term.hasSelection() && !document.hidden && !pointerFine && !touchState && !flingRaf);
        if (!show) { hideHandles(); return; }
        var rect = screenRect();
        if (!rect || rect.width <= 0 || rect.height <= 0) { hideHandles(); return; }
        var aIdx = selAnchor.bufferY * term.cols + selAnchor.col;
        var hIdx = selHead.bufferY * term.cols + selHead.col;
        var first = aIdx <= hIdx ? selAnchor : selHead;
        var last = aIdx <= hIdx ? selHead : selAnchor;
        var cellW = rect.width / term.cols;
        var cellH2 = rect.height / term.rows;
        positionHandle(handleStart, rect.left + first.col * cellW, rect.top + viewportRowOf(first.bufferY) * cellH2);
        positionHandle(handleEnd, rect.left + (last.col + 1) * cellW, rect.top + (viewportRowOf(last.bufferY) + 1) * cellH2);
    }

    function applyHandleDrag() {
        if (!handleDrag || !selAnchor || !selHead || !term.hasSelection()) return;
        var cell = cellOf(handleDrag.x, handleDrag.y);
        if (!cell) return;
        var aIdx = selAnchor.bufferY * term.cols + selAnchor.col;
        var hIdx = selHead.bufferY * term.cols + selHead.col;
        var anchorIsFirst = aIdx <= hIdx;
        if (handleDrag.which === 'start') {
            if (anchorIsFirst) selAnchor = cell; else selHead = cell;
        } else {
            if (anchorIsFirst) selHead = cell; else selAnchor = cell;
        }
        applySelection(selAnchor, selHead);
    }

    function handleEdgeLoop() {
        if (!handleDrag) return;
        var rect = screenRect();
        if (rect) {
            var margin = 40;
            var edge = 0;
            if (handleDrag.y < rect.top + margin) edge = -1;
            else if (handleDrag.y > rect.bottom - margin) edge = 1;
            if (edge) {
                var over = edge < 0 ? rect.top + margin - handleDrag.y : handleDrag.y - (rect.bottom - margin);
                var lines = edge * Math.max(1, Math.min(4, Math.round(over / 12)));
                scrollByLines(lines);
                applyHandleDrag();
            }
        }
        handleDrag.raf = requestAnimationFrame(handleEdgeLoop);
    }

    function endHandleDrag() {
        if (!handleDrag) return;
        var drag = handleDrag;
        handleDrag = null;
        if (drag.raf) cancelAnimationFrame(drag.raf);
        updateHandles();
        if (drag.ended) showMenu(drag.x, drag.y);
    }

    function bindHandle(el, which) {
        if (!el) return;
        el.addEventListener('touchstart', function (event) {
            if (pointerFine || event.touches.length !== 1) return;
            event.preventDefault();
            event.stopPropagation();
            stopFling();
            if (menuOpen) hideMenu(true);
            var point = event.touches[0];
            handleDrag = { which: which, id: point.identifier, x: point.clientX, y: point.clientY, raf: 0, ended: false };
            handleDrag.raf = requestAnimationFrame(handleEdgeLoop);
            updateHandles();
        }, { passive: false, capture: true });
        el.addEventListener('touchmove', function (event) {
            if (!handleDrag) return;
            var point = null;
            for (var i = 0; i < event.touches.length; i++) {
                if (event.touches[i].identifier === handleDrag.id) { point = event.touches[i]; break; }
            }
            if (!point) return;
            event.preventDefault();
            event.stopPropagation();
            handleDrag.x = point.clientX;
            handleDrag.y = point.clientY;
            applyHandleDrag();
        }, { passive: false, capture: true });
        el.addEventListener('touchend', function (event) {
            if (!handleDrag) return;
            for (var i = 0; i < event.changedTouches.length; i++) {
                if (event.changedTouches[i].identifier === handleDrag.id) {
                    handleDrag.x = event.changedTouches[i].clientX;
                    handleDrag.y = event.changedTouches[i].clientY;
                    handleDrag.ended = true;
                    break;
                }
            }
            endHandleDrag();
        }, { passive: true, capture: true });
        el.addEventListener('touchcancel', function () {
            endHandleDrag();
        }, { passive: true, capture: true });
    }

    bindHandle(handleStart, 'start');
    bindHandle(handleEnd, 'end');

    term.onSelectionChange(function () {
        updateHandles();
    });
    term.onScroll(function () {
        updateHandles();
    });

    function onTouchStart(event) {
        if (!root || !root.contains(event.target)) return;
        event.stopPropagation();
        if (event.touches.length !== 1) {
            touchState = null;
            stopFling();
            updateHandles();
            return;
        }
        stopFling();
        if (menuOpen) {
            hideMenu();
            try { term.clearSelection(); } catch (e) { }
        }
        var point = event.touches[0];
        var cell = cellOf(point.clientX, point.clientY);
        if (!cell) return;
        touchState = {
            id: point.identifier, sx: point.clientX, sy: point.clientY,
            x: point.clientX, y: point.clientY, lastY: point.clientY,
            cell: cell, anchor: null, moved: false, longFired: false,
            scrolling: false, extended: false, vel: 0, lastT: performance.now(), timer: null
        };
        touchState.timer = setTimeout(function () {
            if (!touchState) return;
            touchState.longFired = true;
            if (root) root.classList.add('xterm-touch-selecting');
            wordSelectAt(touchState.cell);
            suppressClickUntil = Date.now() + 800;
        }, 500);
        updateHandles();
    }

    function onTouchMove(event) {
        if (!root || !root.contains(event.target)) return;
        event.stopPropagation();
        if (!touchState) return;
        var point = event.touches[0];
        if (!point || point.identifier !== touchState.id) return;
        touchState.x = point.clientX;
        touchState.y = point.clientY;
        var dx = touchState.x - touchState.sx;
        var dy = touchState.y - touchState.sy;
        if (!touchState.moved && dx * dx + dy * dy > 64) {
            touchState.moved = true;
            if (!touchState.longFired) {
                if (touchState.timer) { clearTimeout(touchState.timer); touchState.timer = null; }
                touchState.scrolling = true;
                stopFling();
                touchState.vel = 0;
                touchState.lastT = performance.now();
                touchState.lastY = point.clientY;
            }
        }
        if (touchState.scrolling) {
            var now = performance.now();
            var dyStep = point.clientY - touchState.lastY;
            touchState.lastY = point.clientY;
            var lines = -dyStep / cellHeight();
            scrollByLines(lines);
            var dt = Math.max(1, now - touchState.lastT);
            touchState.lastT = now;
            touchState.vel = touchState.vel * 0.65 + (lines / dt) * 0.35;
            return;
        }
        if (touchState.longFired && touchState.anchor) {
            var cell = cellOf(touchState.x, touchState.y);
            if (cell && Math.abs(cell.row - touchState.cell.row) <= ROW_LIMIT) {
                touchState.extended = true;
                applySelection(touchState.anchor, cell);
            }
            var moveNow = performance.now();
            var moveDt = Math.max(1, moveNow - touchState.lastT);
            var moveSpeed = Math.abs(point.clientY - touchState.lastY) / moveDt;
            touchState.lastT = moveNow;
            touchState.lastY = point.clientY;
            if (moveSpeed > 1.5 && dx * dx + dy * dy > 900) {
                touchState.extended = false;
                touchState.anchor = null;
                touchState.longFired = false;
                touchState.scrolling = true;
                touchState.vel = 0;
                try { term.clearSelection(); } catch (e) { }
                if (root) root.classList.remove('xterm-touch-selecting');
            }
        }
    }

    function onTouchEnd() {
        if (!touchState) return;
        var state = touchState;
        touchState = null;
        if (state.timer) clearTimeout(state.timer);
        if (root) root.classList.remove('xterm-touch-selecting');
        if (state.scrolling) {
            startFling(state.vel);
            return;
        }
        if (state.longFired) {
            if (state.extended) {
                var selected = term.getSelection();
                if (selected) copyText(selected).catch(function () { });
            }
            showMenu(state.x, state.y);
            updateHandles();
            return;
        }
        var endDx = state.x - state.sx;
        var endDy = state.y - state.sy;
        if (endDx * endDx + endDy * endDy < 196) {
            suppressClickUntil = Date.now() + 400;
            if (term.hasSelection()) {
                try { term.clearSelection(); } catch (e) { }
                focusTerminal();
                updateHandles();
                return;
            }
            if (!state.moved && term.modes && term.modes.mouseTracking && term.modes.mouseTracking !== 'none') {
                sendTap(state.cell.col, state.cell.row);
            }
            focusTerminal();
        }
        updateHandles();
    }

    function onTouchCancel() {
        if (touchState) {
            if (touchState.timer) clearTimeout(touchState.timer);
            touchState = null;
        }
        if (root) root.classList.remove('xterm-touch-selecting');
        stopFling();
    }

    root.addEventListener('touchstart', onTouchStart, { passive: false, capture: true });
    root.addEventListener('touchmove', onTouchMove, { passive: false, capture: true });
    root.addEventListener('touchend', onTouchEnd, { passive: true });
    root.addEventListener('touchcancel', onTouchCancel, { passive: true });
    root.addEventListener('mousedown', onMouseDown, true);
    root.addEventListener('contextmenu', onContextMenu, true);
    document.addEventListener('contextmenu', function (event) {
        if (wantBrowserMenu(event)) return;
        event.preventDefault();
    }, true);
    document.addEventListener('selectstart', function (event) {
        event.preventDefault();
    }, true);

    term.attachCustomKeyEventHandler(function (event) {
        if (event.type === 'keydown' && !event.isComposing && root) {
            var keyTa = root.querySelector('.xterm-helper-textarea');
            if (keyTa && keyTa.value) keyTa.value = '';
        }
        var key = event.key;
        if ((event.ctrlKey || event.metaKey) && (key === 'a' || key === 'A') && !event.isComposing) {
            doSelectAll();
            return false;
        }
        if ((event.ctrlKey || event.metaKey) && (key === 'v' || key === 'V') && !event.isComposing) {
            return false;
        }
        if ((event.ctrlKey || event.metaKey) && (key === 'c' || key === 'C') && term.hasSelection()) {
            var selected = term.getSelection();
            if (selected) {
                copyText(selected).catch(function () { });
                term.clearSelection();
                return false;
            }
        }
        return true;
    });

    var keysBar = document.getElementById('term_keys');
    var modState = { ctrl: false, alt: false };

    function setMod(name, active) {
        modState[name] = active;
        var button = keysBar.querySelector('[data-key="' + name + '"]');
        if (button) button.classList.toggle('active', active);
    }

    function resetMods() {
        setMod('ctrl', false);
        setMod('alt', false);
    }

    function ctrlTransform(ch) {
        var map = {
            ' ': '\x00', '2': '\x00', '@': '\x00', '[': '\x1b', '3': '\x1b',
            '\\': '\x1c', '4': '\x1c', ']': '\x1d', '5': '\x1d',
            '^': '\x1e', '6': '\x1e', '_': '\x1f', '7': '\x1f', '/': '\x1f',
            '?': '\x7f', '8': '\x7f'
        };
        if (map[ch]) return map[ch];
        var code = ch.charCodeAt(0);
        if (code >= 97 && code <= 122) return String.fromCharCode(code - 96);
        if (code >= 64 && code <= 95) return String.fromCharCode(code - 64);
        return ch;
    }

    function withMods(base) {
        var modifier = 1;
        if (modState.alt) modifier += 1;
        if (modState.ctrl) modifier += 4;
        if (modifier === 1) return base;
        var match = /^\x1b\[([A-Za-z])$/.exec(base);
        if (match) return '\x1b[1;' + modifier + match[1];
        match = /^\x1b\[(\d+)(~)$/.exec(base);
        if (match) return '\x1b[' + match[1] + ';' + modifier + '~';
        return base;
    }

    function handleKeyAction(name) {
        if (name === 'ctrl') { setMod('ctrl', !modState.ctrl); return; }
        if (name === 'alt') { setMod('alt', !modState.alt); return; }
        var arrows = { left: 'D', up: 'A', right: 'C', down: 'B' };
        var plain = { pipe: '|', slash: '/', tilde: '~', dash: '-', backtick: '`', semicolon: ';', quote: "'" };
        var sequence = null;
        if (arrows[name]) sequence = withMods('\x1b[' + arrows[name]);
        else if (name === 'esc') sequence = '\x1b';
        else if (name === 'tab') sequence = withMods('\t');
        else if (name === 'home') sequence = withMods('\x1b[H');
        else if (name === 'end') sequence = withMods('\x1b[F');
        else if (name === 'pgup') sequence = withMods('\x1b[5~');
        else if (name === 'pgdn') sequence = withMods('\x1b[6~');
        else if (plain[name]) {
            var ch = plain[name];
            if (modState.ctrl && modState.alt) sequence = '\x1b' + ctrlTransform(ch);
            else if (modState.ctrl) sequence = ctrlTransform(ch);
            else if (modState.alt) sequence = '\x1b' + ch;
            else sequence = ch;
        }
        if (sequence === null) return;
        sendInput(sequence);
        resetMods();
        focusTerminal();
    }

    Array.prototype.forEach.call(keysBar.querySelectorAll('button[data-key]'), function (button) {
        button.addEventListener('pointerdown', function (event) {
            event.preventDefault();
        });
        button.addEventListener('mousedown', function (event) {
            event.preventDefault();
        });
        button.addEventListener('click', function (event) {
            event.preventDefault();
            handleKeyAction(button.getAttribute('data-key'));
        });
    });

    function syncViewport() {
        var inset = 0;
        if (window.visualViewport) {
            inset = Math.max(0, Math.round(window.innerHeight - window.visualViewport.height - window.visualViewport.offsetTop));
        }
        document.documentElement.style.setProperty('--kb-inset', inset + 'px');
    }
    if (window.visualViewport) {
        window.visualViewport.addEventListener('resize', syncViewport);
        window.visualViewport.addEventListener('scroll', syncViewport);
    }
    syncViewport();

    var textarea = getTextArea();
    if (textarea) {
        textarea.setAttribute('autocapitalize', 'off');
        textarea.setAttribute('autocorrect', 'off');
        textarea.setAttribute('spellcheck', 'false');
    }

    fitNow();
    connect();
    if (window.matchMedia && window.matchMedia('(pointer: fine)').matches) focusTerminal();
})();
