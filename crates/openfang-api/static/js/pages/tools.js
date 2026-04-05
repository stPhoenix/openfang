// Tools page — browsable catalog of all installed tools (built-in + MCP)
document.addEventListener('alpine:init', function() {
  Alpine.data('toolsPage', function() {
    return {
      loading: true,
      loadError: '',
      tools: [],
      searchQuery: '',
      filterSource: 'all',

      async loadTools() {
        this.loading = true;
        this.loadError = '';
        try {
          var data = await OpenFangAPI.get('/api/tools');
          this.tools = (data.tools || []).map(function(t) {
            return {
              name: t.name,
              description: t.description || '',
              source: t.source || 'built-in',
              schema: t.input_schema || {}
            };
          });
        } catch(e) {
          this.loadError = 'Failed to load tools: ' + e.message;
        }
        this.loading = false;
      },

      get filteredTools() {
        var self = this;
        return this.tools.filter(function(t) {
          if (self.filterSource !== 'all' && t.source !== self.filterSource) return false;
          if (self.searchQuery) {
            var q = self.searchQuery.toLowerCase();
            if (t.name.toLowerCase().indexOf(q) === -1 &&
                t.description.toLowerCase().indexOf(q) === -1) return false;
          }
          return true;
        });
      },

      get builtinCount() {
        return this.tools.filter(function(t) { return t.source === 'built-in'; }).length;
      },

      get mcpCount() {
        return this.tools.filter(function(t) { return t.source === 'mcp'; }).length;
      },

      toolCategory: function(name) {
        if (/^file_|^apply_patch/.test(name)) return 'Filesystem';
        if (/^web_/.test(name)) return 'Web';
        if (/^shell_/.test(name)) return 'Shell';
        if (/^agent_/.test(name)) return 'Agents';
        if (/^memory_/.test(name)) return 'Memory';
        if (/^task_/.test(name)) return 'Tasks';
        if (/^event_/.test(name)) return 'Events';
        if (/^knowledge_/.test(name)) return 'Knowledge';
        if (/^image_|^media_|^location_/.test(name)) return 'Media';
        if (/^browser_/.test(name)) return 'Browser';
        if (/^cron_/.test(name)) return 'Scheduler';
        return 'Other';
      },

      schemaParams: function(schema) {
        if (!schema || !schema.properties) return [];
        var required = schema.required || [];
        return Object.keys(schema.properties).map(function(k) {
          var p = schema.properties[k];
          return {
            name: k,
            type: p.type || 'any',
            description: p.description || '',
            required: required.indexOf(k) !== -1
          };
        });
      }
    };
  });
});
