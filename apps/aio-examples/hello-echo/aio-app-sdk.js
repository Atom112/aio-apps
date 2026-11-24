/*
 * @aio/app-sdk — micro-app client for AIO's host bridge.
 *
 * Framework-agnostic, no build step, no dependencies: drop this file into your bundle and
 * load it with `<script src="aio-app-sdk.js"></script>` (the host CSP allows subresources
 * from the bundle's own origin). It wraps the postMessage protocol documented in
 * docs/en/development/micro-apps.md:
 *
 *   const app = await AIO.connect();
 *   app.applyTheme();                            // inject theme.css + tokens
 *   await app.chat([{ role: 'user', content: 'hi' }]);
 *   await app.kv.set('note', 'hello');
 *
 * Security: the SDK never sees provider keys or host storage. Every call is forwarded to the
 * Rust bridge, which authorizes it against the capabilities the user granted.
 */
(function attachAioSdk(global) {
  'use strict';

  var BRIDGE_VERSION = 1;
  var DEFAULT_TIMEOUT_MS = 15000;

  /** Injects `theme.css` and the resolved `--aio-*` values into this document. */
  function applyTheme(theme) {
    if (!theme) return;
    if (theme.css) {
      var style = document.getElementById('aio-theme');
      if (!style) {
        style = document.createElement('style');
        style.id = 'aio-theme';
        document.head.appendChild(style);
      }
      style.textContent = theme.css;
    }
    if (theme.tokens) {
      Object.keys(theme.tokens).forEach(function (name) {
        if (name.indexOf('--') === 0) {
          document.documentElement.style.setProperty(name, theme.tokens[name]);
        }
      });
    }
    if (theme.mode) document.documentElement.dataset.aioTheme = theme.mode;
  }

  function bytesToBase64(data) {
    var bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    var binary = '';
    for (var i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function base64ToText(encoded) {
    var binary = atob(String(encoded || ''));
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  function createClient(init, options) {
    var nextId = 1;
    var pending = {};
    var themeListeners = [];

    function call(method, params) {
      return new Promise(function (resolve, reject) {
        var id = 'r' + nextId++;
        var timer = setTimeout(function () {
          if (!pending[id]) return;
          delete pending[id];
          reject({ code: 'bridge_timeout', message: 'host did not answer ' + method });
        }, options.timeoutMs);
        pending[id] = {
          resolve: function (value) {
            clearTimeout(timer);
            resolve(value);
          },
          reject: function (error) {
            clearTimeout(timer);
            reject(error);
          },
        };
        window.parent.postMessage(
          { aio: 'rpc', id: id, method: method, params: params || {} },
          '*',
        );
      });
    }

    window.addEventListener('message', function (event) {
      var data = event.data || {};
      if (data.aio === 'rpc-reply') {
        var entry = pending[data.id];
        if (!entry) return;
        delete pending[data.id];
        if (data.ok) entry.resolve(data.result);
        else entry.reject(data.error || { code: 'unknown', message: 'bridge error' });
        return;
      }
      if (data.aio === 'theme') {
        client.theme = data.theme;
        applyTheme(data.theme);
        themeListeners.forEach(function (listener) {
          try {
            listener(data.theme);
          } catch (error) {
            console.error('[aio] theme listener failed', error);
          }
        });
      }
    });

    var client = {
      bridgeVersion: init.bridgeVersion || BRIDGE_VERSION,
      appId: init.appId,
      capabilities: init.capabilities || [],
      uiMode: init.uiMode || 'canvas',
      locale: init.locale || 'en-US',
      theme: init.theme || null,
      /** Like `app.chat` but with the whole conversation array. */
      chat: function (messages, chatOptions) {
        var params = { messages: messages };
        if (chatOptions && chatOptions.maxTokens) params.maxTokens = chatOptions.maxTokens;
        if (chatOptions && typeof chatOptions.temperature === 'number') {
          params.temperature = chatOptions.temperature;
        }
        return call('ai/chat', params);
      },
      kv: {
        get: function (key) {
          return call('storage/kv/get', { key: key }).then(function (result) {
            return result && result.entry ? result.entry : null;
          });
        },
        set: function (key, value) {
          return call('storage/kv/set', { key: key, value: value });
        },
        del: function (key) {
          return call('storage/kv/del', { key: key }).then(function (result) {
            return !!(result && result.deleted);
          });
        },
        list: function (prefix) {
          return call('storage/kv/list', { prefix: prefix || '' }).then(function (result) {
            return (result && result.items) || [];
          });
        },
      },
      /** App-owned files (`storage.file`). Names are flat: no directories. */
      files: {
        /**
         * Writes a file. Pass a string for text or an ArrayBuffer/Uint8Array for binary.
         * @returns {Promise<{name: string, size: number}>}
         */
        write: function (name, data) {
          var payload = { name: name };
          if (typeof data === 'string') payload.text = data;
          else payload.base64 = bytesToBase64(data);
          return call('storage/file/write', payload);
        },
        /** @returns {Promise<{name: string, size: number, base64: string}>} */
        read: function (name) {
          return call('storage/file/read', { name: name });
        },
        /** Reads a file and decodes it as UTF-8 text. */
        readText: function (name) {
          return client.files.read(name).then(function (file) {
            return base64ToText(file.base64);
          });
        },
        /** @returns {Promise<Array<{name: string, size: number, modifiedAt: number}>>} */
        list: function () {
          return call('storage/file/list', {}).then(function (result) {
            return (result && result.items) || [];
          });
        },
        /** @returns {Promise<boolean>} deleted */
        del: function (name) {
          return call('storage/file/delete', { name: name }).then(function (result) {
            return !!(result && result.deleted);
          });
        },
      },
      /**
       * Opens the host's file picker and copies the chosen file into app storage
       * (`import.file`). The app never sees the path.
       */
      importFile: function (name) {
        return call('import/file', name ? { name: name } : {}).then(function (result) {
          return result && result.entry;
        });
      },
      /** Opens the host's save dialog and writes one stored file out (`export.file`). */
      exportFile: function (name, suggestedName) {
        return call(
          'export/file',
          suggestedName ? { name: name, suggestedName: suggestedName } : { name: name },
        );
      },
      /**
       * Embeds texts with the host's configured embedding model (`ai.embed`).
       * Rejects with `embedding_unavailable` when no model is installed.
       * @param {string[]} texts 1-32 strings
       * @returns {Promise<{model: string, dim: number, vectors: number[][]}>}
       */
      embed: function (texts) {
        return call('ai/embed', { texts: texts });
      },
      /** The app's own vector index (`vector.self`); embeddings come from the app. */
      vectors: {
        upsert: function (id, text, vector, meta) {
          var params = { id: id, text: text, vector: vector };
          if (meta) params.meta = meta;
          return call('vector/upsert', params);
        },
        /** @returns {Promise<Array<{id: string, text: string, score: number}>>} */
        query: function (vector, topK) {
          return call(
            'vector/query',
            topK ? { vector: vector, topK: topK } : { vector: vector },
          ).then(function (result) {
            return (result && result.items) || [];
          });
        },
        del: function (id) {
          return call('vector/delete', { id: id }).then(function (result) {
            return !!(result && result.deleted);
          });
        },
        list: function () {
          return call('vector/list', {}).then(function (result) {
            return (result && result.items) || [];
          });
        },
      },
      /** Host toast (`ui.notify`). */
      notify: function (text) {
        return call('ui/notify', { text: String(text) });
      },
      /** Re-reads the host theme (`ui.theme`); the `onTheme` push already covers live changes. */
      refreshTheme: function () {
        return call('ui/theme', {}).then(function (result) {
          if (result && result.theme) {
            client.theme = result.theme;
            applyTheme(result.theme);
          }
          return client.theme;
        });
      },
      /**
       * Generates an image through the host-selected model (`ai/image`) and stores it as an
       * app file. @returns {Promise<{name: string, size: number, mime: string}>}
       */
      image: function (prompt) {
        return call('ai/image', { prompt: prompt });
      },
      /** Opens a link in the system browser (`ui.openLink`); the host validates the scheme. */
      openLink: function (url) {
        return call('ui/openLink', { url: String(url) });
      },
      /** Applies the current theme (call once at startup if you do not call connect's option). */
      applyTheme: function () {
        applyTheme(client.theme);
      },
      /** Subscribes to host theme changes (dark/light, accent colour). */
      onTheme: function (listener) {
        themeListeners.push(listener);
        return function () {
          themeListeners = themeListeners.filter(function (item) {
            return item !== listener;
          });
        };
      },
      /** Raw bridge access for capabilities the SDK does not wrap yet. */
      call: call,
    };
    return client;
  }

  /**
   * Performs the handshake and resolves with the client.
   *
   * @param {{timeoutMs?: number, applyTheme?: boolean, onTheme?: (theme: object) => void}} [options]
   */
  function connect(options) {
    var opts = options || {};
    var timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
    return new Promise(function (resolve, reject) {
      var settled = false;
      var timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        reject({ code: 'handshake_timeout', message: 'host did not complete the handshake' });
      }, timeoutMs);

      function onMessage(event) {
        var data = event.data || {};
        if (data.aio !== 'initialize') return;
        settled = true;
        clearTimeout(timer);
        window.removeEventListener('message', onMessage);
        var client = createClient(data, { timeoutMs: timeoutMs });
        if (opts.applyTheme !== false) client.applyTheme();
        if (opts.onTheme) client.onTheme(opts.onTheme);
        resolve(client);
      }

      window.addEventListener('message', onMessage);
      window.parent.postMessage({ aio: 'hello', sdkVersion: '0.1.0' }, '*');
    });
  }

  global.AIO = {
    connect: connect,
    applyTheme: applyTheme,
    version: '0.1.0',
  };
})(window);
