function evolutionPage() {
  return {
    // State
    config: { enabled: false, provider: 'anthropic', model: 'claude-haiku-4-5-20251001', api_key: null, base_url: null, batch_size: 20 },
    analyses: [],
    stats: { total_analyses: 0, sessions_analyzed: 0, sessions_pending: 0, avg_completion_rate: 0, total_suggestions: 0, total_tool_issues: 0 },
    providers: [],
    allModels: [],
    providersLoading: false,
    modelsLoading: false,
    loading: true,
    loadError: '',
    running: false,
    saving: false,
    showConfig: false,
    selectedAnalysis: null,
    lastRunResult: null,
    analyzerAgentId: null,
    skillRecords: [],
    toolQualityRecords: [],
    activeTab: 'analyses',
    triggerRunning: false,

    // Lifecycle
    async loadData() {
      this.loading = true;
      this.loadError = '';
      try {
        await Promise.all([this.loadConfig(), this.loadStats(), this.loadAnalyses(), this.loadModelOptions(), this.loadAgent(), this.loadSkillRecords(), this.loadToolQuality()]);
      } catch (e) {
        this.loadError = e.message || 'Failed to load evolution data.';
      }
      this.loading = false;
    },

    async loadConfig() {
      var data = await OpenFangAPI.get('/api/evolve/config');
      if (data) this.config = data;
    },

    async saveConfig() {
      this.saving = true;
      try {
        var body = {
          enabled: this.config.enabled,
          provider: this.config.provider,
          model: this.config.model,
          batch_size: parseInt(this.config.batch_size) || 20
        };
        if (this.config.api_key) body.api_key = this.config.api_key;
        if (this.config.base_url) body.base_url = this.config.base_url;
        await OpenFangAPI.put('/api/evolve/config', body);
        OpenFangToast.success('Configuration saved');
      } catch (e) {
        OpenFangToast.error('Failed to save: ' + (e.message || e));
      }
      this.saving = false;
    },

    async loadStats() {
      var data = await OpenFangAPI.get('/api/evolve/stats');
      if (data) this.stats = data;
    },

    async loadModelOptions() {
      this.providersLoading = true;
      this.modelsLoading = true;
      try {
        var results = await Promise.all([
          OpenFangAPI.get('/api/providers').catch(function() { return { providers: [] }; }),
          OpenFangAPI.get('/api/models?available=true').catch(function() { return { models: [] }; })
        ]);
        this.providers = results[0].providers || [];
        this.allModels = results[1].models || [];
      } catch(e) { /* ignore */ }
      this.providersLoading = false;
      this.modelsLoading = false;
    },

    get filteredModels() {
      if (!this.config.provider) return this.allModels;
      var prov = this.config.provider;
      return this.allModels.filter(function(m) { return m.provider === prov; });
    },

    onProviderChange() {
      var filtered = this.filteredModels;
      if (filtered.length === 0) { this.config.model = ''; return; }
      var self = this;
      var currentValid = filtered.some(function(m) { return m.id === self.config.model; });
      if (!currentValid) {
        this.config.model = filtered[0].id;
      }
    },

    async loadAgent() {
      try {
        var data = await OpenFangAPI.get('/api/evolve/agent');
        this.analyzerAgentId = data.agent_id || null;
      } catch (e) { this.analyzerAgentId = null; }
    },

    async loadAnalyses() {
      var data = await OpenFangAPI.get('/api/evolve/analyses?limit=50');
      if (data && data.analyses) this.analyses = data.analyses;
    },

    async runAnalysis() {
      this.running = true;
      this.lastRunResult = null;
      try {
        var data = await OpenFangAPI.post('/api/evolve/run', {});
        this.lastRunResult = data;
        OpenFangToast.success('Analyzed ' + (data.analyzed || 0) + ' sessions');
        await Promise.all([this.loadStats(), this.loadAnalyses(), this.loadAgent()]);
      } catch (e) {
        OpenFangToast.error('Analysis failed: ' + (e.message || e));
      }
      this.running = false;
    },

    selectAnalysis(a) {
      this.selectedAnalysis = (this.selectedAnalysis && this.selectedAnalysis.id === a.id) ? null : a;
    },

    async loadSkillRecords() {
      try {
        var data = await OpenFangAPI.get('/api/evolve/skills');
        this.skillRecords = Array.isArray(data) ? data : [];
      } catch (e) { this.skillRecords = []; }
    },

    async loadToolQuality() {
      try {
        var data = await OpenFangAPI.get('/api/evolve/tools');
        this.toolQualityRecords = Array.isArray(data) ? data : [];
      } catch (e) { this.toolQualityRecords = []; }
    },

    async triggerDegradation() {
      this.triggerRunning = true;
      try {
        var data = await OpenFangAPI.post('/api/evolve/trigger/degradation', {});
        OpenFangToast.success(data.message || 'Degradation check complete');
      } catch (e) {
        OpenFangToast.error('Trigger failed: ' + (e.message || e));
      }
      this.triggerRunning = false;
    },

    async triggerMetrics() {
      this.triggerRunning = true;
      try {
        var data = await OpenFangAPI.post('/api/evolve/trigger/metrics', {});
        OpenFangToast.success(data.message || 'Metric check complete');
      } catch (e) {
        OpenFangToast.error('Trigger failed: ' + (e.message || e));
      }
      this.triggerRunning = false;
    },

    skillAppliedRate(s) {
      return s.total_selections > 0 ? ((s.total_applied / s.total_selections) * 100).toFixed(0) + '%' : '-';
    },
    skillCompletionRate(s) {
      return s.total_applied > 0 ? ((s.total_completions / s.total_applied) * 100).toFixed(0) + '%' : '-';
    },
    toolSuccessRate(t) {
      return t.total_calls > 0 ? ((t.success_count / t.total_calls) * 100).toFixed(0) + '%' : '-';
    },
    toolPenalty(t) {
      if (t.total_calls < 3) return '1.00';
      var recentSuccess = t.recent_executions ? t.recent_executions.filter(function(e) { return e.success; }).length / t.recent_executions.length : 1;
      if (recentSuccess >= 0.4) return '1.00';
      return Math.max(0.2, 0.3 + (recentSuccess / 0.4) * 0.7).toFixed(2);
    },

    // Helpers
    fmtTime(ts) {
      if (!ts) return '-';
      var d = new Date(ts);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },
    completionPct() {
      return (this.stats.avg_completion_rate * 100).toFixed(0) + '%';
    },
    qualityClass(q) {
      if (q === 'good') return 'badge-success';
      if (q === 'partial') return 'badge-warning';
      if (q === 'poor') return 'badge-danger';
      return 'badge-dim';
    },
    kindClass(k) {
      if (k === 'fix') return 'badge-danger';
      if (k === 'derived') return 'badge-warning';
      if (k === 'captured') return 'badge-success';
      return 'badge-dim';
    },
    issueClass(t) {
      if (t === 'failure') return 'badge-danger';
      if (t === 'misuse') return 'badge-warning';
      if (t === 'unnecessary') return 'badge-dim';
      if (t === 'missing') return 'badge-info';
      return '';
    },
    shortId(id) {
      return id ? id.substring(0, 8) : '-';
    }
  };
}
