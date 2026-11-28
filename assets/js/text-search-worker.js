/* Whole-document search preserves JavaScript RegExp semantics across all
 * boundaries. Running in a worker lets the editor stop pathological patterns. */
'use strict';
self.onmessage = function(event) {
    var request = event.data || {};
    var text = String(request.text || '');
    var re;
    try { re = new RegExp(request.source, request.flags); }
    catch (error) { self.postMessage({ type: 'error', message: 'Invalid regular expression' }); return; }
    var matches = [];
    var match;
    var lastReport = Date.now();
    while ((match = re.exec(text))) {
        if (matches.length >= 20000) {
            self.postMessage({ type: 'error', message: 'Too many matches to display' });
            return;
        }
        matches.push({ index: match.index, length: match[0].length });
        if (!match[0].length) re.lastIndex++;
        if ((matches.length & 4095) === 0 && Date.now() - lastReport >= 100) {
            self.postMessage({ type: 'progress', count: matches.length, done: Math.min(text.length, re.lastIndex) });
            lastReport = Date.now();
        }
    }
    self.postMessage({ type: 'done', matches: matches });
};
