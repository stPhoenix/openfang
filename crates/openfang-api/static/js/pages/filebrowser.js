// File Browser page — read-only browser for agent workspaces and hands dirs.
// Renders markdown via existing renderMarkdown(); other text shown as <pre>.
document.addEventListener('alpine:init', function() {
  Alpine.data('filebrowserPage', function() {
    return {
      loading: false,
      loadError: '',
      roots: [],
      currentRoot: null,     // 'workspaces' | 'hands' | null (roots overview)
      currentPath: '',       // relative path under currentRoot
      entries: [],
      viewingFile: null,     // {name, content, mime, size_bytes, isMarkdown, relPath}

      async init() {
        await this.loadRoots();
        // Handoff from agent detail modal "Open Workdir".
        var handoff = Alpine.store('fileBrowser');
        if (handoff && handoff.root) {
          var rootName = handoff.root;
          var relPath = handoff.relPath || '';
          if (!relPath && handoff.absPath) {
            relPath = this._stripRootPrefix(rootName, handoff.absPath);
          }
          Alpine.store('fileBrowser', {});
          await this.openRoot(rootName);
          if (relPath) {
            await this.navigateTo(relPath);
          }
        }
      },

      _stripRootPrefix: function(rootName, absPath) {
        var root = this.roots.find(function(r) { return r.name === rootName; });
        if (!root || !root.path) return '';
        var base = root.path.replace(/\/+$/, ''); // safe: simple trailing-slash strip on bounded OS path
        var p = absPath.replace(/\/+$/, ''); // safe: simple trailing-slash strip on bounded OS path
        if (p === base) return '';
        if (p.indexOf(base + '/') === 0) return p.slice(base.length + 1);
        return ''; // not under this root; fall back to root listing
      },

      async loadRoots() {
        this.loading = true;
        this.loadError = '';
        try {
          var data = await OpenFangAPI.get('/api/files/roots');
          this.roots = data.roots || [];
        } catch(e) {
          this.loadError = 'Failed to load roots: ' + (e && e.message ? e.message : e);
        }
        this.loading = false;
      },

      async openRoot(name) {
        this.currentRoot = name;
        this.currentPath = '';
        this.viewingFile = null;
        await this._loadDir();
      },

      async navigateTo(relPath) {
        this.currentPath = (relPath || '').replace(/^\/+|\/+$/g, ''); // safe: leading/trailing-slash strip on bounded OS path
        this.viewingFile = null;
        await this._loadDir();
      },

      async navigateUp() {
        if (!this.currentPath) return;
        var parts = this.currentPath.split('/');
        parts.pop();
        await this.navigateTo(parts.join('/'));
      },

      async _loadDir() {
        if (!this.currentRoot) return;
        this.loading = true;
        this.loadError = '';
        try {
          var qs = 'root=' + encodeURIComponent(this.currentRoot) +
                   '&path=' + encodeURIComponent(this.currentPath || '');
          var data = await OpenFangAPI.get('/api/files/list?' + qs);
          this.entries = data.entries || [];
        } catch(e) {
          this.loadError = 'Failed to list directory: ' + (e && e.message ? e.message : e);
          this.entries = [];
        }
        this.loading = false;
      },

      backToRoots() {
        this.currentRoot = null;
        this.currentPath = '';
        this.entries = [];
        this.viewingFile = null;
      },

      openEntry(e) {
        if (!e) return;
        if (e.is_dir) {
          var next = this.currentPath ? (this.currentPath + '/' + e.name) : e.name;
          this.navigateTo(next);
        } else {
          this.openFile(e);
        }
      },

      async openFile(e) {
        var rel = this.currentPath ? (this.currentPath + '/' + e.name) : e.name;
        this.loading = true;
        this.loadError = '';
        try {
          var qs = 'root=' + encodeURIComponent(this.currentRoot) +
                   '&path=' + encodeURIComponent(rel);
          var data = await OpenFangAPI.get('/api/files/read?' + qs);
          this.viewingFile = {
            name: data.name,
            content: data.content || '',
            mime: data.mime || 'text/plain',
            size_bytes: data.size_bytes || 0,
            truncated: !!data.truncated,
            isMarkdown: /\.md$|\.markdown$/i.test(e.name),
            relPath: rel,
          };
        } catch(err) {
          // Fall back: server signaled binary or too-large — open download instead.
          var msg = err && err.message ? err.message : String(err);
          if (/binary|too large|413|415/i.test(msg)) {
            this.downloadEntry(e);
            this.loadError = '';
          } else {
            this.loadError = 'Failed to read file: ' + msg;
          }
        }
        this.loading = false;
      },

      downloadEntry(e) {
        if (!e || e.is_dir) return;
        var rel = this.currentPath ? (this.currentPath + '/' + e.name) : e.name;
        this._download(rel);
      },

      downloadCurrent() {
        if (!this.viewingFile) return;
        this._download(this.viewingFile.relPath);
      },

      _download(rel) {
        var url = '/api/files/download?root=' + encodeURIComponent(this.currentRoot) +
                  '&path=' + encodeURIComponent(rel);
        var a = document.createElement('a');
        a.href = url;
        a.rel = 'noopener';
        a.target = '_self';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      },

      closeFile() {
        this.viewingFile = null;
      },

      get renderedMarkdown() {
        if (!this.viewingFile || !this.viewingFile.isMarkdown) return '';
        if (typeof renderMarkdown === 'function') {
          return renderMarkdown(this.viewingFile.content);
        }
        return escapeHtml(this.viewingFile.content);
      },

      get breadcrumb() {
        var crumbs = [];
        if (!this.currentRoot) return crumbs;
        crumbs.push({ label: this.currentRoot, path: '' });
        if (this.currentPath) {
          var acc = '';
          var parts = this.currentPath.split('/');
          for (var i = 0; i < parts.length; i++) {
            acc = acc ? (acc + '/' + parts[i]) : parts[i];
            crumbs.push({ label: parts[i], path: acc });
          }
        }
        return crumbs;
      },

      formatSize(n) {
        if (!n && n !== 0) return '';
        if (n < 1024) return n + ' B';
        if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
        return (n / 1024 / 1024).toFixed(2) + ' MiB';
      },
    };
  });
});
