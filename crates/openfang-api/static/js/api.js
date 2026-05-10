// OpenFang API Client — Fetch wrapper, WebSocket manager, auth injection, toast notifications
'use strict';

// ── Toast Notification System ──
var OpenFangToast = (function() {
  var _container = null;
  var _toastId = 0;

  function getContainer() {
    if (!_container) {
      _container = document.getElementById('toast-container');
      if (!_container) {
        _container = document.createElement('div');
        _container.id = 'toast-container';
        _container.className = 'toast-container';
        document.body.appendChild(_container);
      }
    }
    return _container;
  }

  function toast(message, type, duration) {
    type = type || 'info';
    duration = duration || 4000;
    var id = ++_toastId;
    var el = document.createElement('div');
    el.className = 'toast toast-' + type;
    el.setAttribute('data-toast-id', id);

    var msgSpan = document.createElement('span');
    msgSpan.className = 'toast-msg';
    msgSpan.textContent = message;
    el.appendChild(msgSpan);

    var closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.textContent = '\u00D7';
    closeBtn.onclick = function() { dismissToast(el); };
    el.appendChild(closeBtn);

    el.onclick = function(e) { if (e.target === el) dismissToast(el); };
    getContainer().appendChild(el);

    // Auto-dismiss
    if (duration > 0) {
      setTimeout(function() { dismissToast(el); }, duration);
    }
    return id;
  }

  function dismissToast(el) {
    if (!el || el.classList.contains('toast-dismiss')) return;
    el.classList.add('toast-dismiss');
    setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 300);
  }

  function success(msg, duration) { return toast(msg, 'success', duration); }
  function error(msg, duration) { return toast(msg, 'error', duration || 6000); }
  function warn(msg, duration) { return toast(msg, 'warn', duration || 5000); }
  function info(msg, duration) { return toast(msg, 'info', duration); }

  // Styled confirmation modal — replaces native confirm()
  function confirm(title, message, onConfirm) {
    var overlay = document.createElement('div');
    overlay.className = 'confirm-overlay';

    var modal = document.createElement('div');
    modal.className = 'confirm-modal';

    var titleEl = document.createElement('div');
    titleEl.className = 'confirm-title';
    titleEl.textContent = title;
    modal.appendChild(titleEl);

    var msgEl = document.createElement('div');
    msgEl.className = 'confirm-message';
    msgEl.textContent = message;
    modal.appendChild(msgEl);

    var actions = document.createElement('div');
    actions.className = 'confirm-actions';

    var cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-ghost confirm-cancel';
    cancelBtn.textContent = 'Cancel';
    actions.appendChild(cancelBtn);

    var okBtn = document.createElement('button');
    okBtn.className = 'btn btn-danger confirm-ok';
    okBtn.textContent = 'Confirm';
    actions.appendChild(okBtn);

    modal.appendChild(actions);
    overlay.appendChild(modal);

    function close() { if (overlay.parentNode) overlay.parentNode.removeChild(overlay); document.removeEventListener('keydown', onKey); }
    cancelBtn.onclick = close;
    okBtn.onclick = function() { close(); if (onConfirm) onConfirm(); };
    overlay.addEventListener('click', function(e) { if (e.target === overlay) close(); });

    function onKey(e) { if (e.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);

    document.body.appendChild(overlay);
    okBtn.focus();
  }

  return {
    toast: toast,
    success: success,
    error: error,
    warn: warn,
    info: info,
    confirm: confirm
  };
})();

// ── Friendly Error Messages ──
function friendlyError(status, serverMsg) {
  if (status === 0 || !status) return 'Cannot reach daemon — is openfang running?';
  if (status === 401) return 'Not authorized — check your API key';
  if (status === 403) return 'Permission denied';
  if (status === 404) return serverMsg || 'Resource not found';
  if (status === 429) return 'Rate limited — slow down and try again';
  if (status === 413) return 'Request too large';
  if (status === 500) return 'Server error — check daemon logs';
  if (status === 502 || status === 503) return 'Daemon unavailable — is it running?';
  return serverMsg || 'Unexpected error (' + status + ')';
}

// ── API Client ──
var OpenFangAPI = (function() {
  var BASE = window.location.origin;
  var WS_BASE = BASE.replace(/^http/, 'ws');
  var _authToken = '';

  // Connection state tracking
  var _connectionState = 'connected';
  var _reconnectAttempt = 0;
  var _connectionListeners = [];

  function setAuthToken(token) { _authToken = token; }

  function headers() {
    var h = { 'Content-Type': 'application/json' };
    if (_authToken) h['Authorization'] = 'Bearer ' + _authToken;
    return h;
  }

  function setConnectionState(state) {
    if (_connectionState === state) return;
    _connectionState = state;
    _connectionListeners.forEach(function(fn) { fn(state); });
  }

  function onConnectionChange(fn) { _connectionListeners.push(fn); }

  function request(method, path, body) {
    var opts = { method: method, headers: headers() };
    if (body !== undefined) opts.body = JSON.stringify(body);
    return fetch(BASE + path, opts).then(function(r) {
      if (_connectionState !== 'connected') setConnectionState('connected');
      if (!r.ok) {
        // On 401, auto-show auth prompt so the user can re-enter their key
        if (r.status === 401 && typeof Alpine !== 'undefined') {
          try {
            var store = Alpine.store('app');
            if (store && !store.showAuthPrompt) {
              _authToken = '';
              localStorage.removeItem('openfang-api-key');
              store.showAuthPrompt = true;
            }
          } catch(e2) { /* ignore Alpine errors */ }
        }
        return r.text().then(function(text) {
          var msg = '';
          try {
            var json = JSON.parse(text);
            msg = json.error || r.statusText;
          } catch(e) {
            msg = r.statusText;
          }
          throw new Error(friendlyError(r.status, msg));
        });
      }
      var ct = r.headers.get('content-type') || '';
      if (ct.indexOf('application/json') >= 0) return r.json();
      return r.text().then(function(t) {
        try { return JSON.parse(t); } catch(e) { return { text: t }; }
      });
    }).catch(function(e) {
      if (e.name === 'TypeError' && e.message.includes('Failed to fetch')) {
        setConnectionState('disconnected');
        throw new Error('Cannot connect to daemon — is openfang running?');
      }
      throw e;
    });
  }

  function get(path) { return request('GET', path); }
  function post(path, body) { return request('POST', path, body); }
  function put(path, body) { return request('PUT', path, body); }
  function patch(path, body) { return request('PATCH', path, body); }
  function del(path, body) { return request('DELETE', path, body); }

    // WebSocket manager with auto-reconnect.
    //
    // Reconnect policy is intentionally infinite (mirrors Open WebUI / Socket.IO
    // behavior): network blips, daemon restarts, or laptop sleep should never
    // permanently downgrade the user to HTTP-only mode. Backoff caps at 30 s with
    // jitter; the `online` event triggers an immediate retry when the OS reports
    // network recovery.
  var _ws = null;
  var _wsCallbacks = {};
  var _wsConnected = false;
  var _wsAgentId = null;
  var _reconnectTimer = null;
  var _reconnectAttempts = 0;
    var _heartbeatTimer = null;
    var HEARTBEAT_MS = 30000;
    var RECONNECT_CAP_MS = 30000;
    var _stillTryingNotified = false;
    var _onlineHooked = false;

    function _stopHeartbeat() {
        if (_heartbeatTimer) {
            clearInterval(_heartbeatTimer);
            _heartbeatTimer = null;
        }
    }

    function _startHeartbeat() {
        _stopHeartbeat();
        _heartbeatTimer = setInterval(function () {
            // wsSend returns false if readyState !== OPEN; the next event will
            // surface the failure and trigger reconnect via socket.onclose.
            wsSend({type: 'ping'});
        }, HEARTBEAT_MS);
    }

    // Tracks the in-flight LLM stream id (set by stream_snapshot, cleared by
    // response/silent_complete/error). Lets chat.js match terminal events
    // to the correct generation across reconnects.
    var _currentStreamId = null;

    // Resume cursor: highest `seq` seen on the current stream. On reconnect
    // we ask the server "send everything after seq N for stream X" instead of
    // re-bootstrapping from the cumulative snapshot. The server falls back to
    // a snapshot if the ring buffer no longer covers the gap, so this is safe
    // even when the daemon was restarted.
    var _lastSeq = -1;
    var _lastStreamId = null;

    function noteEventSeq(streamId, seq) {
        if (!streamId) return;
        if (streamId !== _lastStreamId) {
            _lastStreamId = streamId;
            _lastSeq = -1;
        }
        if (typeof seq === 'number' && seq > _lastSeq) _lastSeq = seq;
    }

    function getCurrentStreamId() {
        return _currentStreamId;
    }

    function setCurrentStreamId(id) {
        _currentStreamId = id;
        if (id == null) {
            // Stream finished — drop the resume cursor so a brand-new stream
            // doesn't accidentally inherit a stale `since_seq` from this one.
            _lastSeq = -1;
            _lastStreamId = null;
        }
    }

    function wsConnect(agentId, callbacks) {
    wsDisconnect();
    _wsCallbacks = callbacks || {};
    _wsAgentId = agentId;
    _reconnectAttempts = 0;
        _stillTryingNotified = false;
        _currentStreamId = null;
        if (!_onlineHooked && typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
            _onlineHooked = true;
            window.addEventListener('online', function () {
                // OS reports network recovery — cancel pending backoff and try now.
                if (_wsAgentId && !_wsConnected) {
                    if (_reconnectTimer) {
                        clearTimeout(_reconnectTimer);
                        _reconnectTimer = null;
                    }
                    _reconnectAttempts = 0;
                    _doConnect(_wsAgentId);
                }
            });
        }
    _doConnect(agentId);
  }

  function _doConnect(agentId) {
    try {
      var url = WS_BASE + '/api/agents/' + agentId + '/ws';
        var qs = [];
        if (_authToken) qs.push('token=' + encodeURIComponent(_authToken));
        // Resume cursor: if we have a known last seq for an in-flight stream,
        // ask the server to replay the gap from its ring buffer instead of
        // re-sending the cumulative snapshot.
        if (_lastStreamId && _lastSeq >= 0) {
            qs.push('stream_id=' + encodeURIComponent(_lastStreamId));
            qs.push('since_seq=' + _lastSeq);
        }
        if (qs.length) url += '?' + qs.join('&');
      var socket = new WebSocket(url);
      _ws = socket;

      socket.onopen = function() {
        // Guard: ignore if this socket was superseded by a newer connection
        if (_ws !== socket) return;
        _wsConnected = true;
        _reconnectAttempts = 0;
          _stillTryingNotified = false;
        setConnectionState('connected');
          _startHeartbeat();
        if (_reconnectAttempt > 0) {
          OpenFangToast.success('Reconnected');
          _reconnectAttempt = 0;
        }
        if (_wsCallbacks.onOpen) _wsCallbacks.onOpen();
      };

      socket.onmessage = function(e) {
        try {
          var data = JSON.parse(e.data);
        } catch(parseErr) {
          return; // Ignore malformed JSON frames
        }
          // Update resume cursor BEFORE dispatch so a reconnect triggered by
          // an exception in the handler still has the latest seq.
          if (data && data.stream_id && typeof data.seq === 'number') {
              noteEventSeq(data.stream_id, data.seq);
          }
        // Dispatch outside try/catch so handler errors are not swallowed
        if (_wsCallbacks.onMessage) _wsCallbacks.onMessage(data);
      };

      socket.onclose = function(e) {
        // Guard: only update state if this is still the active socket.
        // A superseded socket closing must not null-out the new connection.
        if (_ws !== socket) return;
        _wsConnected = false;
        _ws = null;
          _stopHeartbeat();
          // Infinite reconnect with capped exponential backoff + jitter. Only
          // a clean close (1000) or an explicit `wsDisconnect` stops retrying.
          if (_wsAgentId && e.code !== 1000) {
          _reconnectAttempts++;
          _reconnectAttempt = _reconnectAttempts;
          setConnectionState('reconnecting');
          if (_reconnectAttempts === 1) {
            OpenFangToast.warn('Connection lost, reconnecting...');
          } else if (_reconnectAttempts === 6 && !_stillTryingNotified) {
              // After ~30 s of failed retries, surface a one-shot warn so the
              // user knows we're still trying instead of silently looping.
              _stillTryingNotified = true;
              OpenFangToast.warn('Still trying to reconnect...');
          }
              var exp = Math.min(_reconnectAttempts - 1, 5);
              var delay = Math.min(1000 * Math.pow(2, exp), RECONNECT_CAP_MS);
              delay = delay + Math.floor(Math.random() * 1000); // jitter
              _reconnectTimer = setTimeout(function () {
                  if (_wsAgentId) _doConnect(_wsAgentId);
              }, delay);
          return;
        }
        if (_wsCallbacks.onClose) _wsCallbacks.onClose();
      };

      socket.onerror = function() {
        // Guard: ignore errors from superseded sockets
        if (_ws !== socket) return;
        _wsConnected = false;
        if (_wsCallbacks.onError) _wsCallbacks.onError();
      };
    } catch(e) {
      _wsConnected = false;
        // Synchronous failure (e.g. blocked by mixed-content / CSP). Schedule
        // a backoff retry — onclose won't fire because the socket never opened.
        if (_wsAgentId) {
            _reconnectAttempts++;
            var expE = Math.min(_reconnectAttempts - 1, 5);
            var delayE = Math.min(1000 * Math.pow(2, expE), RECONNECT_CAP_MS);
            delayE = delayE + Math.floor(Math.random() * 1000);
            _reconnectTimer = setTimeout(function () {
                if (_wsAgentId) _doConnect(_wsAgentId);
            }, delayE);
        }
    }
  }

  function wsDisconnect() {
    _wsAgentId = null;
      _reconnectAttempts = 0;
      _stillTryingNotified = false;
    if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
      _stopHeartbeat();
    if (_ws) { _ws.close(1000); _ws = null; }
    _wsConnected = false;
      setConnectionState('disconnected');
  }

  function wsSend(data) {
    if (_ws && _ws.readyState === WebSocket.OPEN) {
      _ws.send(JSON.stringify(data));
      return true;
    }
    return false;
  }

  function isWsConnected() { return _wsConnected; }

  function getConnectionState() { return _connectionState; }

  function getToken() { return _authToken; }

  function upload(agentId, file) {
    var hdrs = {};
    if (_authToken) hdrs['Authorization'] = 'Bearer ' + _authToken;
	var form = new FormData();
    form.append('file', file);
    form.append('filename', file.name);
    return fetch(BASE + '/api/agents/' + agentId + '/upload', {
      method: 'POST',
      headers: hdrs,
      body: form
    }).then(function(r) {
      if (!r.ok) throw new Error('Upload failed');
      return r.json();
    });
  }

  return {
    setAuthToken: setAuthToken,
    getToken: getToken,
    get: get,
    post: post,
    put: put,
    patch: patch,
    del: del,
    delete: del,
    upload: upload,
    wsConnect: wsConnect,
    wsDisconnect: wsDisconnect,
    wsSend: wsSend,
    isWsConnected: isWsConnected,
    getConnectionState: getConnectionState,
      onConnectionChange: onConnectionChange,
      getCurrentStreamId: getCurrentStreamId,
      setCurrentStreamId: setCurrentStreamId
  };
})();
