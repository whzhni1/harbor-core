
(function (global) {
	'use strict';

	var activeSearchControllers = new Set();
	global.addEventListener('pagehide', function () {
		activeSearchControllers.forEach(function(controller) { controller.abort(); });
		activeSearchControllers.clear();
	});

	function endpoint() {
		var configured = global.HarborFile && global.HarborFile.io;
		return typeof configured === 'string' && configured ? configured : '/io';
	}

	function validSessionID(value) {
		return typeof value === 'string' && /^[a-fA-F0-9]{32}$/.test(value) && !/^0{32}$/.test(value);
	}

	function sessionID() {
		var value = '';
		if (global.rpc && typeof global.rpc.getSessionID === 'function') {
			try { value = global.rpc.getSessionID(); } catch (error) {}
		}
		if (validSessionID(value))
			return value;
		value = global.L && global.L.env && global.L.env.sessionid;
		if (validSessionID(value))
			return value;
		value = global.HarborFile && global.HarborFile.sessionid;
		return validSessionID(value) ? value : '';
	}

	function queryString(params) {
		var out = [];
		for (var k in params)
			if (params[k] !== undefined && params[k] !== null)
				out.push(encodeURIComponent(k) + '=' + encodeURIComponent(params[k]));
		return out.join('&');
	}

	function byteInteger(value) { return Number.isSafeInteger(value) && value >= 0; }

	// /io errors are JSON, but retain compatibility with older text responses.
	function responseError(res, prefix) {
		return res.text().then(function (text) {
			var message = text.trim();
			try { message = JSON.parse(text).message || message; } catch (e) {}
			throw new Error(prefix + ': HTTP ' + res.status + (message ? ': ' + message : ''));
		});
	}

	// A lost response, malformed response, or server-side failure may happen
	// after a write was published. Never silently describe that as a safe
	// failure or retry it; tell the caller to inspect the target first.
	function writeError(message, uncertain) {
		var warning = 'The write outcome is unknown. Check the file before retrying; the operation may still be running.';
		if (global.HarborFile && typeof global.HarborFile.tr === 'function') warning = global.HarborFile.tr(warning);
		var error = new Error(String(message || 'Write failed') + (uncertain ? '\n' + warning : ''));
		error.outcomeUnknown = uncertain;
		return error;
	}
	function mutationRequest(url, options, name, envelope) {
		return fetch(url, options).then(function(res) {
			return res.text().then(function(text) {
				var j;
				try { j = JSON.parse(text); } catch (_) { throw writeError(name + ': HTTP ' + res.status, true); }
				if (!j || typeof j !== 'object' || Array.isArray(j) || !Number.isInteger(j.code) ||
				    (j.code === 0 && (!j.data || typeof j.data !== 'object' || Array.isArray(j.data))))
					throw writeError(name + ': invalid response', true);
				if (!res.ok || j.code !== 0) {
					var unknown = res.status >= 500 || !!(j && j.data && j.data.outcome_unknown);
					throw writeError(j && j.message || (name + ': HTTP ' + res.status), unknown);
				}
				return envelope ? j : j.data;
			}, function(error) { throw writeError(error && error.message, true); });
		}, function(error) { throw writeError(error && error.message, true); });
	}

	function createIO(context) {
	function qs(params) { return queryString(Object.assign({}, params, context)); }
	var HarborIO = {

		getSessionID: sessionID,
		requestURL: function(mode, path, extra) { return endpoint() + '?' + qs(Object.assign({ mode: mode, path: path, sessionid: sessionID() }, extra || {})); },

		download: function (path, filename) {
			var target = 'harbor_dl_' + Date.now() + '_' + Math.floor(Math.random() * 1e6);

			var iframe = document.createElement('iframe');
			iframe.name = target;
			iframe.style.display = 'none';

			var linkPath = String(path).split('/').filter(Boolean).map(encodeURIComponent).join('/');
			var form = document.createElement('form');
			form.method = 'POST';
			form.action = endpoint() + (linkPath ? '/' + linkPath : '');
			form.target = target;
			form.style.display = 'none';

			var fields = {
				mode: 'download',
				sessionid: sessionID(),
				path: path,
				filename: filename || path.split('/').pop()
			};

			Object.assign(fields, context);
			for (var k in fields) {
				var input = document.createElement('input');
				input.type = 'hidden';
				input.name = k;
				input.value = fields[k];
				form.appendChild(input);
			}

			document.body.appendChild(iframe);
			document.body.appendChild(form);
			form.submit();

			setTimeout(function () {
				form.remove();
				iframe.remove();
			}, 60000);

			return true;
		},

		inlineURL: function (path, mimetype) {
			return endpoint() + '?' + qs({
				mode: 'inline',
				sessionid: sessionID(),
				path: path,
				mimetype: mimetype
			});
		},

		thumbnailURL: function (path, cachePath) {
			return endpoint() + '?' + qs({
				mode: 'thumbnail',
				sessionid: sessionID(),
				path: path,
				cache: cachePath
			});
		},

		slice: function (path, offset, length) {
			if (!byteInteger(offset) || !byteInteger(length) || !byteInteger(offset + length)) return Promise.reject(new Error('Invalid byte range'));
			var url = endpoint() + '?' + qs({
				mode: 'slice',
				sessionid: sessionID(),
				path: path,
				offset: offset,
				length: length
			});

			return fetch(url, { credentials: 'same-origin' }).then(function (res) {
				if (!res.ok)
					return responseError(res, 'slice failed');

				var total = parseInt(res.headers.get('X-Harbor-Total') || '0', 10);
				var off = parseInt(res.headers.get('X-Harbor-Offset') || '0', 10);

				if (!byteInteger(total) || !byteInteger(off) || off !== Math.min(offset, total)) throw new Error('Invalid slice response offset');
				return res.arrayBuffer().then(function (buf) {
					if (buf.byteLength !== Math.min(length, 8 * 1024 * 1024, total - off)) throw new Error('Incomplete slice response');
					return { buffer: buf, offset: off, total: total };
				});
			});
		},

		patch: function (path, offset, bytes, expectedSize) {
			if (!byteInteger(offset) || expectedSize != null && !byteInteger(expectedSize)) return Promise.reject(new Error('Invalid byte offset or file size'));
			var url = endpoint() + '?' + qs({
				mode: 'patch',
				sessionid: sessionID(),
				path: path,
				offset: offset,
				expected_size: expectedSize
			});

			return mutationRequest(url, {
				method: 'POST', credentials: 'same-origin',
				headers: { 'Content-Type': 'application/octet-stream' }, body: bytes
			}, 'patch failed', false);
		},

		splice: function (path, start, end, bytes, expectedSize) {
			if (!byteInteger(start) || !byteInteger(end) || end < start || expectedSize != null && !byteInteger(expectedSize)) return Promise.reject(new Error('Invalid byte range or file size'));
			var url = endpoint() + '?' + qs({
				mode: 'splice',
				sessionid: sessionID(),
				path: path,
				start: start,
				end: end,
				expected_size: expectedSize
			});

			return mutationRequest(url, {
				method: 'POST', credentials: 'same-origin',
				headers: { 'Content-Type': 'application/octet-stream' }, body: bytes
			}, 'splice failed', false);
		},

		search: function (path, needle, opts) {
			opts = opts || {};

			var url = endpoint() + '?' + qs({
				mode: 'search',
				sessionid: sessionID(),
				path: path,
				q: needle,
				encoding: opts.encoding || 'text',
				regex: opts.regex ? 1 : 0,
				start: opts.start || 0,
				last: opts.last ? 1 : 0,
				before: opts.before,
				limit: opts.limit || 100,
				scan_bytes: opts.scanBytes,
				ignorecase: opts.ignoreCase ? 1 : 0
			});

			var controller = typeof AbortController === 'undefined' ? null : new AbortController();
			var external_signal = opts.signal;
			var abort_search = function() { if (controller) controller.abort(); };
			if (controller) {
				activeSearchControllers.add(controller);
				if (external_signal) {
					if (external_signal.aborted) controller.abort();
					else external_signal.addEventListener('abort', abort_search, { once: true });
				}
			}
			return fetch(url, { credentials: 'same-origin', signal: controller ? controller.signal : external_signal }).then(function (res) {
				return res.json().then(function (j) {
					if (!res.ok || j.code !== 0)
						throw new Error(j.message || ('search failed: HTTP ' + res.status));
					return j.data;
				});
			}).finally(function() {
				if (controller) {
					activeSearchControllers.delete(controller);
					if (external_signal) external_signal.removeEventListener('abort', abort_search);
				}
			});
		},

		replaceAll: function (path, needle, replacement, opts) {
			opts = opts || {};
			var q = {
				mode: 'replace_all',
				sessionid: sessionID(),
				path: path,
				q: needle,
				r: replacement,
				encoding: opts.encoding || 'text',
				rencoding: opts.rencoding || opts.encoding || 'text',
				regex: opts.regex ? 1 : 0,
				ignorecase: opts.ignoreCase ? 1 : 0,
				range: opts.range || null,
				progress_id: opts.progressId
			};
			if (opts.stageSrc) {
				q.stage = 1;
				q.src = opts.stageSrc;
			}
			var url = endpoint() + '?' + qs(q);

			return mutationRequest(url, {
				method: 'POST', credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: ''
			}, 'replace_all failed', false);
		},

		stageCommit: function (path) {
			var url = endpoint() + '?' + qs({
				mode: 'stage_commit',
				sessionid: sessionID(),
				path: path
			});
			return mutationRequest(url, { method: 'POST', credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: '' }, 'commit failed', true);
		},

		stageDiscard: function (path) {
			var url = endpoint() + '?' + qs({
				mode: 'stage_discard',
				sessionid: sessionID(),
				path: path
			});
			return fetch(url, { method: 'POST', credentials: 'same-origin',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: '' })
				.then(function (res) { return res.json(); })
				.then(function (j) { return j; });
		},

		replaceProgress: function (path, progressId) {
			var url = endpoint() + '?' + qs({
				mode: 'replace_progress',
				sessionid: sessionID(),
				path: path,
				progress_id: progressId
			});
			return fetch(url, { credentials: 'same-origin' })
				.then(function (res) { return res.json(); })
				.then(function (j) {
					return (j && j.code === 0) ? j.data : { done: 0, total: 0 };
				});
		},

		readAll: function (path) {
			var url = endpoint() + '?' + qs({
				mode: 'inline',
				sessionid: sessionID(),
				path: path,
				mimetype: 'application/octet-stream'
			});

			return fetch(url, { credentials: 'same-origin' }).then(function (res) {
				if (!res.ok)
					return responseError(res, 'read failed');
				return res.arrayBuffer();
			});
		}
	};

	return HarborIO;
	}
	global.HarborIO = createIO({});
	global.HarborIO.forDevice = function(item) { return createIO({ device_id: item.device_id, device_revision: item.device_revision || '' }); };
})(window);
