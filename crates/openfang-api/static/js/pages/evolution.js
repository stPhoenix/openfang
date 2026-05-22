function evolutionPage() {
  return {
    // ── Sub-view routing ──
    evolutionView: 'overview',  // 'overview' | 'skills' | 'skill-detail' | 'suggestions'

    // ── Existing state ──
      config: {
          enabled: false,
          provider: 'anthropic',
          model: 'claude-haiku-4-5-20251001',
          api_key: null,
          base_url: null,
          batch_size: 20,
          dedup_enabled: true,
          apply_max_per_run: 20,
          analyze_schedule: null,
          apply_schedule: null
      },
      // Schedule UI bindings: cron expression strings the user types. Empty = no schedule.
      analyzeCronExpr: '',
      applyCronExpr: '',
      // Last batch-apply preview / run result for the panel. Hydrated on mount
      // from /api/evolve/batch-apply/status so reload restores spinner + results.
      batchApply: {
          running: false,
          operation: null,
          current: 0,
          total: 0,
          stepLabel: null,
          lastSummary: null,
          lastPreview: null,
          startedAt: null,
          finishedAt: null,
          error: null
      },
      _batchApplyPollHandle: null,
      // Slow heartbeat: ~5s. Detects externally-triggered batch applies (cron,
      // curl, other tabs) and starts the fast poller so the dashboard catches
      // up without needing the user to reload.
      _batchApplyHeartbeat: null,
    analyses: [],
    stats: { total_analyses: 0, sessions_analyzed: 0, sessions_pending: 0, avg_completion_rate: 0, total_suggestions: 0, total_tool_issues: 0 },
    providers: [],
    allModels: [],
    providersLoading: false,
    modelsLoading: false,
    loading: true,
    loadError: '',
    running: false,
    progress: { current: 0, total: 0, lastSessionId: null, lastStatus: null },
    _evolveSource: null,
    _pollHandle: null,

    // ── Evolve-execute queue ──
      executeProgress: {
          running: false,
          current: 0,
          total: 0,
          succeeded: 0,
          failed: 0,
          declined: 0,
          queue: [],
          lastStatus: null,
          lastChangeSummary: null
      },
    _executeSource: null,
    _executePollHandle: null,
    saving: false,
    showConfig: false,
      showAdvanced: false,
    selectedAnalysis: null,
    lastRunResult: null,
    analyzerAgentId: null,
    skillRecords: [],
    triggerRunning: false,

    // ── Skills library state ──
    skillSearch: '',
    skillSort: 'score',
    skillOriginFilter: '',
    skillTagFilter: '',
    skillClasses: [],

      // ── Pagination state (per tab) ──
      overviewPage: 1,
      overviewPageSize: 25,
      overviewTotal: 0,
      overviewSort: 'analyzed_at',
      overviewSortDesc: true,
      suggestionsPage: 1,
      suggestionsPageSize: 25,
      suggestionsSortDesc: true,
      skillsPage: 1,
      skillsPageSize: 25,
      skillDetailPage: 1,
      skillDetailPageSize: 25,
      // Map of selected suggestion _key → true (for multi-select bulk delete).
      selectedSuggestions: {},

      // ── Skill detail state ──
    selectedClassName: null,
    selectedClassSkills: [],
    graphNodes: [],
    graphEdges: [],
    graphHover: null,
    graphCanvas: null,
    graphCtx: null,
    graphPositions: [],

    // ── Version drawer ──
    showVersionDrawer: false,
    drawerSkill: null,
    drawerDiffFiles: [],
    drawerSourceTab: 0,

    // ════════════════════════════════════════
    // Lifecycle
    // ════════════════════════════════════════
    async loadData() {
        this._tearDown();
      this.loading = true;
      this.loadError = '';
      try {
          await Promise.all([this.loadConfig(), this.loadStats(), this.loadCost(), this.loadAnalyses(), this.loadModelOptions(), this.loadAgent(), this.loadSkillRecords(), this.loadRunStatus(), this.loadExecuteStatus(), this.loadBatchApplyStatus()]);
        this.buildSkillClasses();
      } catch (e) {
        this.loadError = e.message || 'Failed to load evolution data.';
      }
      this.loading = false;
    },

      // Close any open EventSources and timers — call from loadData() and from
      // an unmount hook to prevent stacked SSE connections on remount.
      _tearDown() {
          if (this._evolveSource) {
              try {
                  this._evolveSource.close();
              } catch (_) {
              }
              this._evolveSource = null;
          }
          if (this._executeSource) {
              try {
                  this._executeSource.close();
              } catch (_) {
              }
              this._executeSource = null;
          }
          if (this._pollHandle) {
              clearInterval(this._pollHandle);
              this._pollHandle = null;
          }
          if (this._executePollHandle) {
              clearInterval(this._executePollHandle);
              this._executePollHandle = null;
          }
          if (this._batchApplyPollHandle) {
              clearInterval(this._batchApplyPollHandle);
              this._batchApplyPollHandle = null;
          }
          if (this._batchApplyHeartbeat) {
              clearInterval(this._batchApplyHeartbeat);
              this._batchApplyHeartbeat = null;
          }
      },

      destroy() {
          this._tearDown();
      },

      cost: {this_month_usd: 0, cap_usd: null, agents: {}},
      async loadCost() {
          try {
              var data = await OpenFangAPI.get('/api/evolve/cost');
              if (data) this.cost = data;
          } catch (_) { /* ignore */
          }
      },

      // ════════════════════════════════════════
    // API loaders (unchanged)
    // ════════════════════════════════════════
    async loadConfig() {
      var data = await OpenFangAPI.get('/api/evolve/config');
      if (data) this.config = data;
        // Hydrate schedule expression inputs from the persisted CronSchedule shape.
        this.analyzeCronExpr = (this.config.analyze_schedule && this.config.analyze_schedule.kind === 'cron')
            ? (this.config.analyze_schedule.expr || '') : '';
        this.applyCronExpr = (this.config.apply_schedule && this.config.apply_schedule.kind === 'cron')
            ? (this.config.apply_schedule.expr || '') : '';
    },
    async saveConfig() {
      this.saving = true;
      try {
          // Send the full config so server-side defaults aren't reset on PUT.
          var body = Object.assign({}, this.config);
          body.enabled = !!this.config.enabled;
          body.dedup_enabled = !!this.config.dedup_enabled;
          body.batch_size = parseInt(this.config.batch_size) || 20;
          if (!body.api_key) delete body.api_key;
          if (!body.base_url) delete body.base_url;
          if (!body.evolver_model) delete body.evolver_model;
          if (body.max_monthly_cost_usd === '' || body.max_monthly_cost_usd === null) {
              delete body.max_monthly_cost_usd;
          }
          if (body.apply_max_per_run === '' || body.apply_max_per_run === null) {
              delete body.apply_max_per_run;
          } else {
              body.apply_max_per_run = parseInt(body.apply_max_per_run) || 20;
          }
          // Pack schedule inputs into CronSchedule shape; empty = null (removes cron job).
          body.analyze_schedule = this.analyzeCronExpr
              ? {kind: 'cron', expr: this.analyzeCronExpr, tz: null}
              : null;
          body.apply_schedule = this.applyCronExpr
              ? {kind: 'cron', expr: this.applyCronExpr, tz: null}
              : null;
        await OpenFangAPI.put('/api/evolve/config', body);
        OpenFangToast.success('Configuration saved');
          await this.loadCost();
      } catch (e) { OpenFangToast.error('Failed to save: ' + (e.message || e)); }
      this.saving = false;
    },

      // ── Batch apply controls ──
      // Hydrate the batch-apply snapshot on mount so a reloading page resumes
      // the spinner + last preview/summary without waiting for a click.
      async loadBatchApplyStatus() {
          try {
              var s = await OpenFangAPI.get('/api/evolve/batch-apply/status');
              if (!s) return;
              this._applyBatchApplySnapshot(s);
              if (s.running) this._startBatchApplyPolling();
          } catch (_) { /* ignore — endpoint may be down */
          }
          // Heartbeat is started exactly once per page mount; subsequent calls
          // (from buttons or the heartbeat itself) skip the guard.
          this._startBatchApplyHeartbeat();
      },
      _startBatchApplyHeartbeat() {
          if (this._batchApplyHeartbeat) return;
          var self = this;
          this._batchApplyHeartbeat = setInterval(async function () {
              // Skip if the fast poller is already covering us.
              if (self._batchApplyPollHandle) return;
              try {
                  var s = await OpenFangAPI.get('/api/evolve/batch-apply/status');
                  if (!s) return;
                  self._applyBatchApplySnapshot(s);
                  if (s.running) self._startBatchApplyPolling();
              } catch (_) {
              }
          }, 5000);
      },
      _applyBatchApplySnapshot(s) {
          this.batchApply.running = !!s.running;
          this.batchApply.operation = s.operation || null;
          this.batchApply.current = s.current || 0;
          this.batchApply.total = s.total || 0;
          this.batchApply.stepLabel = s.step_label || null;
          this.batchApply.lastPreview = s.last_preview || null;
          this.batchApply.lastSummary = s.last_run_summary || null;
          this.batchApply.startedAt = s.started_at || null;
          this.batchApply.finishedAt = s.finished_at || null;
          this.batchApply.error = s.last_error || null;
      },
      _startBatchApplyPolling() {
          if (this._batchApplyPollHandle) return;
          var self = this;
          this._batchApplyPollHandle = setInterval(async function () {
              try {
                  var s = await OpenFangAPI.get('/api/evolve/batch-apply/status');
                  if (!s) return;
                  var wasRunning = self.batchApply.running;
                  self._applyBatchApplySnapshot(s);
                  if (!s.running && wasRunning) {
                      clearInterval(self._batchApplyPollHandle);
                      self._batchApplyPollHandle = null;
                      // Refresh related data once the run finishes.
                      try {
                          await Promise.all([self.loadStats(), self.loadAnalyses(), self.loadSkillRecords()]);
                          self.buildSkillClasses();
                      } catch (_) {
                      }
                  }
              } catch (_) {
              }
          }, 1500);
      },
      async previewBatchApply() {
          this.batchApply.running = true;
          this.batchApply.operation = 'preview';
          this.batchApply.error = null;
          // Start the poller before the request returns — server's snapshot
          // already reflects running=true, so reload mid-call keeps the spinner.
          this._startBatchApplyPolling();
          try {
              var data = await OpenFangAPI.get('/api/evolve/batch-apply/preview');
              this.batchApply.lastPreview = data;
              OpenFangToast.success('Preview: ' + (data.total_pending || 0) + ' pending, ' +
                  (data.superseded || 0) + ' would dedup, ' + (data.survivors || 0) + ' survivors');
          } catch (e) {
              this.batchApply.error = e.message || String(e);
              OpenFangToast.error('Preview failed: ' + this.batchApply.error);
          }
          // Final state is authoritative from the server — refresh now and stop
          // the poller if the server already flipped running=false.
          try {
              var s = await OpenFangAPI.get('/api/evolve/batch-apply/status');
              if (s) this._applyBatchApplySnapshot(s);
              if (!s || !s.running) {
                  if (this._batchApplyPollHandle) {
                      clearInterval(this._batchApplyPollHandle);
                      this._batchApplyPollHandle = null;
                  }
              }
          } catch (_) {
          }
      },
      async runBatchApply() {
          if (!confirm('Run batch apply now? This will dedup pending suggestions and execute the survivors.')) return;
          this.batchApply.running = true;
          this.batchApply.operation = 'run';
          this.batchApply.error = null;
          this._startBatchApplyPolling();
          try {
              var data = await OpenFangAPI.post('/api/evolve/batch-apply/run', {});
              this.batchApply.lastSummary = (data && data.summary) || JSON.stringify(data);
              OpenFangToast.success('Batch apply complete');
              await Promise.all([this.loadStats(), this.loadAnalyses(), this.loadSkillRecords()]);
          } catch (e) {
              this.batchApply.error = e.message || String(e);
              OpenFangToast.error('Batch apply failed: ' + this.batchApply.error);
          }
          try {
              var s = await OpenFangAPI.get('/api/evolve/batch-apply/status');
              if (s) this._applyBatchApplySnapshot(s);
              if (!s || !s.running) {
                  if (this._batchApplyPollHandle) {
                      clearInterval(this._batchApplyPollHandle);
                      this._batchApplyPollHandle = null;
                  }
              }
          } catch (_) {
          }
      },
    async loadStats() {
      var data = await OpenFangAPI.get('/api/evolve/stats');
      if (data) this.stats = data;
    },
    // Recover progress for a batch that started in a previous page session.
    // Mount hook → if server says running, start the status poller so the
    // progress bar lights up immediately without needing the SSE stream.
    async loadRunStatus() {
      try {
        var s = await OpenFangAPI.get('/api/evolve/run/status');
        if (!s || !s.running) return;
        this.running = true;
        this.progress.current = s.current || 0;
        this.progress.total = s.total || 0;
        this.progress.lastSessionId = s.last_session_id || null;
        this.progress.lastStatus = s.last_status || null;
        this._startStatusPolling();
      } catch (_) { /* ignore — endpoint may be down */ }
    },
    _startStatusPolling() {
      if (this._pollHandle) return;
      var self = this;
      this._pollHandle = setInterval(async function() {
        try {
          var s = await OpenFangAPI.get('/api/evolve/run/status');
          if (!s) return;
          self.progress.current = s.current || 0;
          self.progress.total = s.total || 0;
          self.progress.lastSessionId = s.last_session_id || null;
          self.progress.lastStatus = s.last_status || null;
          if (!s.running) {
            clearInterval(self._pollHandle);
            self._pollHandle = null;
            self.running = false;
            if (s.error) {
              OpenFangToast.error('Analysis failed: ' + s.error);
            } else {
              self.lastRunResult = { analyzed: s.analyzed || 0 };
              OpenFangToast.success('Analyzed ' + (s.analyzed || 0) + ' sessions');
            }
            try {
              await Promise.all([self.loadStats(), self.loadAnalyses(), self.loadAgent(), self.loadSkillRecords()]);
              self.buildSkillClasses();
            } catch (_) {}
          }
        } catch (_) { /* keep polling — transient network errors are fine */ }
      }, 1200);
    },
    // ── Evolve-execute progress ──
    // Hydrate the execute snapshot on mount so a reloading page resumes the
    // progress card and badge updates without waiting for the SSE stream.
    async loadExecuteStatus() {
      try {
        var s = await OpenFangAPI.get('/api/evolve/execute/status');
        if (!s) return;
        this._applyExecuteSnapshot(s);
        if (s.running) {
          this._startExecuteStream();
          this._startExecutePolling();
        }
      } catch (_) { /* ignore — endpoint may be down */ }
    },
    _applyExecuteSnapshot(s) {
      this.executeProgress.running = !!s.running;
      this.executeProgress.current = s.current || 0;
      this.executeProgress.total = s.total || 0;
      this.executeProgress.succeeded = s.succeeded || 0;
      this.executeProgress.failed = s.failed || 0;
        this.executeProgress.declined = s.declined || 0;
      this.executeProgress.queue = Array.isArray(s.queue) ? s.queue : [];
      this.executeProgress.lastStatus = s.last_status || null;
      this.executeProgress.lastChangeSummary = s.last_change_summary || null;
    },
    _startExecuteStream() {
      if (this._executeSource) return;
      var self = this;
      var url = '/api/evolve/execute/stream';
      var token = (typeof OpenFangAPI !== 'undefined' && OpenFangAPI.getToken) ? OpenFangAPI.getToken() : null;
      if (token) url += '?token=' + encodeURIComponent(token);
      try { this._executeSource = new EventSource(url); }
      catch (e) { return; }
      this._executeSource.onmessage = function(event) {
        var ev; try { ev = JSON.parse(event.data); } catch (_) { return; }
        if (ev.type === 'item') {
          // Mutate the matching queue entry in-place so the card updates
          // without a status fetch.
          var key = (ev.analysis_id || '') + '|' + (ev.kind || '') + '|' + (ev.description || '');
          var q = self.executeProgress.queue;
          var found = false;
          for (var i = 0; i < q.length; i++) {
            var k = (q[i].analysis_id || '') + '|' + (q[i].kind || '') + '|' + (q[i].description || '');
            if (k === key) {
              q[i].status = ev.status;
              q[i].failure_reason = ev.failure_reason || null;
              q[i].change_summary = ev.change_summary || null;
              found = true;
              break;
            }
          }
          if (!found && ev.status === 'queued') {
            q.push({
              analysis_id: ev.analysis_id || null,
              kind: ev.kind,
              description: ev.description,
              target_skill: ev.target_skill || null,
              status: ev.status,
              failure_reason: null,
              change_summary: null,
            });
            self.executeProgress.total = Math.max(self.executeProgress.total, q.length);
          }
          if (ev.status === 'running') {
            self.executeProgress.current = Math.max(self.executeProgress.current, (ev.index || 0) + 1);
            self.executeProgress.running = true;
          }
            if (ev.status === 'done' || ev.status === 'failed' || ev.status === 'declined') {
            // Refresh row badges (executed_at / failed_at) from the DB.
                // Declined doesn't update DB but UI shows the badge inline.
            self.loadAnalyses().catch(function() {});
          }
        } else if (ev.type === 'completed') {
          self.executeProgress.running = false;
          self.executeProgress.succeeded = ev.succeeded || 0;
          self.executeProgress.failed = ev.failed || 0;
            self.executeProgress.declined = ev.declined || 0;
          var msg = 'Evolved ' + self.executeProgress.succeeded + '/' + self.executeProgress.total;
          if (self.executeProgress.failed > 0) msg += ' (' + self.executeProgress.failed + ' failed)';
            if (self.executeProgress.declined > 0) msg += ' (' + self.executeProgress.declined + ' declined)';
          OpenFangToast.success(msg);
          try { self._executeSource.close(); } catch (_) {}
          self._executeSource = null;
          if (self._executePollHandle) { clearInterval(self._executePollHandle); self._executePollHandle = null; }
          Promise.all([self.loadSkillRecords(), self.loadStats(), self.loadAnalyses()])
            .then(function() { self.buildSkillClasses(); })
            .catch(function() {});
        } else if (ev.type === 'error') {
          OpenFangToast.error('Evolution stream error: ' + (ev.message || 'unknown'));
        }
      };
      this._executeSource.onerror = function() {
        // EventSource auto-retries; rely on poller to detect end-of-run.
      };
    },
    _startExecutePolling() {
      if (this._executePollHandle) return;
      var self = this;
      this._executePollHandle = setInterval(async function() {
        try {
          var s = await OpenFangAPI.get('/api/evolve/execute/status');
          if (!s) return;
          self._applyExecuteSnapshot(s);
          if (!s.running) {
            clearInterval(self._executePollHandle);
            self._executePollHandle = null;
            if (self._executeSource) { try { self._executeSource.close(); } catch (_) {} self._executeSource = null; }
            try { await Promise.all([self.loadStats(), self.loadAnalyses(), self.loadSkillRecords()]); self.buildSkillClasses(); } catch (_) {}
          }
        } catch (_) {}
      }, 1500);
    },
    // True if a suggestion row currently has work pending or running on the
    // execute queue. Used by the row template to keep the spinner visible
    // across reloads.
    isSuggestionExecuting(analysisId, suggestion) {
      var aid = analysisId || '';
      var kind = (suggestion.kind || '').toLowerCase();
      var desc = suggestion.description || '';
      var q = this.executeProgress.queue || [];
      for (var i = 0; i < q.length; i++) {
        if ((q[i].analysis_id || '') === aid
            && (q[i].kind || '') === kind
            && (q[i].description || '') === desc
            && (q[i].status === 'queued' || q[i].status === 'running')) {
          return true;
        }
      }
      return false;
    },

    async loadModelOptions() {
      this.providersLoading = true;
      this.modelsLoading = true;
      try {
        var results = await Promise.all([
          OpenFangAPI.get('/api/providers').catch(function() { return { providers: [] }; }),
          OpenFangAPI.get('/api/models?available=true').catch(function() { return { models: [] }; })
        ]);
          this.providers = (results[0].providers || []).slice().sort(function (a, b) {
              var la = (a.display_name || a.id).toLowerCase();
              var lb = (b.display_name || b.id).toLowerCase();
              return la < lb ? -1 : la > lb ? 1 : 0;
          });
        this.allModels = results[1].models || [];
      } catch(e) { /* ignore */ }
      this.providersLoading = false;
      this.modelsLoading = false;
    },
    get filteredModels() {
        var sortByLabel = function (a, b) {
            var la = (a.display_name || a.id).toLowerCase();
            var lb = (b.display_name || b.id).toLowerCase();
            return la < lb ? -1 : la > lb ? 1 : 0;
        };
        if (!this.config.provider) return this.allModels.slice().sort(sortByLabel);
      var prov = this.config.provider;
        return this.allModels.filter(function (m) {
            return m.provider === prov;
        }).sort(sortByLabel);
    },
    onProviderChange() {
      var filtered = this.filteredModels;
      if (filtered.length === 0) { this.config.model = ''; return; }
      var self = this;
      var currentValid = filtered.some(function(m) { return m.id === self.config.model; });
      if (!currentValid) this.config.model = filtered[0].id;
    },
    async loadAgent() {
      try {
        var data = await OpenFangAPI.get('/api/evolve/agent');
        this.analyzerAgentId = data.agent_id || null;
      } catch (e) { this.analyzerAgentId = null; }
    },
    async loadAnalyses() {
        var limit = this.overviewPageSize || 25;
        var offset = (Math.max(1, this.overviewPage) - 1) * limit;
        var data = await OpenFangAPI.get('/api/evolve/analyses?limit=' + limit + '&offset=' + offset);
        // Response shape: { items, total, limit, offset }
        var items = (data && (data.items || data.analyses)) || [];
        items.forEach(function (a) {
            (a.evolution_suggestions || []).forEach(function (s) {
                s._executing = false;
                s._deleting = false;
            });
        });
        this.analyses = items;
        this.overviewTotal = (data && typeof data.total === 'number') ? data.total : items.length;
    },
    async runAnalysis() {
      if (this.running) return;
      this.running = true;
      this.lastRunResult = null;
      this.progress = { current: 0, total: 0, lastSessionId: null, lastStatus: null };

      var self = this;
      var done = false;

      var finish = function(analyzed, errorMsg) {
        if (done) return;
        done = true;
        if (self._evolveSource) {
          try { self._evolveSource.close(); } catch (_) {}
          self._evolveSource = null;
        }
        if (self._pollHandle) {
          clearInterval(self._pollHandle);
          self._pollHandle = null;
        }
        if (errorMsg) {
          OpenFangToast.error('Analysis failed: ' + errorMsg);
        } else {
          self.lastRunResult = { analyzed: analyzed };
          OpenFangToast.success('Analyzed ' + analyzed + ' sessions');
        }
        Promise.all([self.loadStats(), self.loadAnalyses(), self.loadAgent(), self.loadSkillRecords()])
          .then(function() { self.buildSkillClasses(); })
          .catch(function() {})
          .finally(function() { self.running = false; });
      };

      var url = '/api/evolve/run/stream';
      var token = (typeof OpenFangAPI !== 'undefined' && OpenFangAPI.getToken) ? OpenFangAPI.getToken() : null;
      if (token) url += '?token=' + encodeURIComponent(token);

      try {
        this._evolveSource = new EventSource(url);
      } catch (e) {
        finish(0, e.message || 'EventSource unavailable');
        return;
      }

      this._evolveSource.onmessage = function(event) {
        var ev;
        try { ev = JSON.parse(event.data); } catch (_) { return; }
        if (ev.type === 'started') {
          self.progress.total = ev.total || 0;
          self.progress.current = 0;
        } else if (ev.type === 'item') {
          self.progress.current = (ev.index || 0) + 1;
          self.progress.total = ev.total || self.progress.total;
          self.progress.lastSessionId = ev.session_id || null;
          self.progress.lastStatus = ev.status || null;
        } else if (ev.type === 'completed') {
          finish(ev.analyzed || 0, null);
        } else if (ev.type === 'error') {
          finish(0, ev.error || 'unknown error');
        }
      };

      this._evolveSource.onerror = function() {
        // EventSource auto-retries; only treat as terminal once we've received
        // a `completed` event (done=true) or the stream errors before opening.
        if (done) return;
        if (self._evolveSource && self._evolveSource.readyState === EventSource.CLOSED) {
          finish(0, 'stream connection lost');
        }
      };
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
    async triggerMetrics() {
      this.triggerRunning = true;
      try {
        var data = await OpenFangAPI.post('/api/evolve/trigger/metrics', {});
        OpenFangToast.success(data.message || 'Metric check complete');
        await this.loadSkillRecords();
        this.buildSkillClasses();
      } catch (e) { OpenFangToast.error('Trigger failed: ' + (e.message || e)); }
      this.triggerRunning = false;
    },

    // ════════════════════════════════════════
    // All Suggestions view
    // ════════════════════════════════════════
    suggestionsSearch: '',
    suggestionsKindFilter: '',
    suggestionsSort: 'priority',

    get allSuggestions() {
      var suggestions = [];
      var idx = 0;
      for (var i = 0; i < this.analyses.length; i++) {
        var a = this.analyses[i];
        var es = a.evolution_suggestions || [];
        for (var j = 0; j < es.length; j++) {
          suggestions.push(Object.assign({}, es[j], {
            _analysis: a,
            _key: a.id + '_' + idx++,
            _executing: es[j]._executing || false,
            _deleting: es[j]._deleting || false
          }));
        }
      }
      return suggestions;
    },

    get filteredSuggestions() {
      var self = this;
      var list = this.allSuggestions;
      if (this.suggestionsKindFilter) {
        list = list.filter(function(s) { return (s.kind || '').toLowerCase() === self.suggestionsKindFilter; });
      }
      if (this.suggestionsSearch) {
        var q = this.suggestionsSearch.toLowerCase();
        list = list.filter(function(s) {
          return (s.description || '').toLowerCase().indexOf(q) !== -1
            || (s.target_skill || '').toLowerCase().indexOf(q) !== -1
            || (s.kind || '').toLowerCase().indexOf(q) !== -1;
        });
      }
        var desc = !!this.suggestionsSortDesc;
        var field = this.suggestionsSort || 'priority';
        list.sort(function (a, b) {
            var va = self._sortValue(a, field);
            var vb = self._sortValue(b, field);
            if (va < vb) return desc ? 1 : -1;
            if (va > vb) return desc ? -1 : 1;
            return 0;
        });
        return list;
    },

      // ════════════════════════════════════════
      // Pagination + sort helpers
      // ════════════════════════════════════════
      // Extracts a comparable value for a field across nested rows (e.g.
      // suggestions reference their analysis via `_analysis` for session_id /
      // analyzed_at). String fields lower-cased for stable ordering.
      _sortValue(row, field) {
          if (!row) return '';
          var v;
          if (field === 'session_id' || field === 'session') v = row._analysis ? row._analysis.session_id : '';
          else if (field === 'analyzed_at' || field === 'analyzed') v = row._analysis ? row._analysis.analyzed_at : row.analyzed_at;
          else if (field === 'status') {
              v = row.executed_at ? 2 : (row.failed_at ? 1 : 0);
          } else {
              v = row[field];
          }
          if (v === null || v === undefined) v = '';
          if (typeof v === 'string') return v.toLowerCase();
          return v;
      },

      // Toggle sort: same field → flip direction; new field → set desc default.
      toggleOverviewSort(field) {
          if (this.overviewSort === field) {
              this.overviewSortDesc = !this.overviewSortDesc;
          } else {
              this.overviewSort = field;
              this.overviewSortDesc = true;
          }
          // Only analyzed_at uses server-side ordering; other columns sort the
          // current page client-side.
      },
      toggleSuggestionsSort(field) {
          if (this.suggestionsSort === field) {
              this.suggestionsSortDesc = !this.suggestionsSortDesc;
          } else {
              this.suggestionsSort = field;
              this.suggestionsSortDesc = true;
          }
          this.suggestionsPage = 1;
      },
      sortGlyph(active, current, desc) {
          if (active !== current) return '';
          return desc ? '▼' : '▲';
      },

      // Analyses on the current page, sorted client-side by overviewSort.
      get sortedAnalyses() {
          var self = this;
          var list = this.analyses.slice();
          var desc = !!this.overviewSortDesc;
          var field = this.overviewSort || 'analyzed_at';
      list.sort(function(a, b) {
          var va, vb;
          if (field === 'session_id') {
              va = a.session_id;
              vb = b.session_id;
          } else if (field === 'agent_id') {
              va = a.agent_id;
              vb = b.agent_id;
          } else if (field === 'task_completed') {
              va = a.task_completed ? 1 : 0;
              vb = b.task_completed ? 1 : 0;
          } else if (field === 'tool_issues') {
              va = (a.tool_issues || []).length;
              vb = (b.tool_issues || []).length;
          } else if (field === 'evolution_suggestions') {
              va = (a.evolution_suggestions || []).length;
              vb = (b.evolution_suggestions || []).length;
          } else if (field === 'model_used') {
              va = a.model_used;
              vb = b.model_used;
          } else {
              va = a.analyzed_at;
              vb = b.analyzed_at;
          }
          if (va === null || va === undefined) va = '';
          if (vb === null || vb === undefined) vb = '';
          if (typeof va === 'string') va = va.toLowerCase();
          if (typeof vb === 'string') vb = vb.toLowerCase();
        if (va < vb) return desc ? 1 : -1;
        if (va > vb) return desc ? -1 : 1;
        return 0;
      });
      return list;
    },

      get overviewTotalPages() {
          return Math.max(1, Math.ceil((this.overviewTotal || 0) / Math.max(1, this.overviewPageSize)));
      },

      // Suggestions slice for the current page.
      get paginatedSuggestions() {
          var size = Math.max(1, this.suggestionsPageSize);
          var page = Math.max(1, this.suggestionsPage);
          var list = this.filteredSuggestions;
          // Clamp page if filters shrank the list past the current page.
          var maxPage = Math.max(1, Math.ceil(list.length / size));
          if (page > maxPage) {
              this.suggestionsPage = maxPage;
              page = maxPage;
          }
          var start = (page - 1) * size;
          return list.slice(start, start + size);
      },

      get suggestionsTotalPages() {
          return Math.max(1, Math.ceil(this.filteredSuggestions.length / Math.max(1, this.suggestionsPageSize)));
      },

      get paginatedSkillClasses() {
          var size = Math.max(1, this.skillsPageSize);
          var page = Math.max(1, this.skillsPage);
          var list = this.filteredSkillClasses;
          var maxPage = Math.max(1, Math.ceil(list.length / size));
          if (page > maxPage) {
              this.skillsPage = maxPage;
              page = maxPage;
          }
          var start = (page - 1) * size;
          return list.slice(start, start + size);
      },

      get skillsTotalPages() {
          return Math.max(1, Math.ceil(this.filteredSkillClasses.length / Math.max(1, this.skillsPageSize)));
      },

      get paginatedClassSkills() {
          var size = Math.max(1, this.skillDetailPageSize);
          var page = Math.max(1, this.skillDetailPage);
          var list = this.selectedClassSkills || [];
          var maxPage = Math.max(1, Math.ceil(list.length / size));
          if (page > maxPage) {
              this.skillDetailPage = maxPage;
              page = maxPage;
          }
          var start = (page - 1) * size;
          return list.slice(start, start + size);
      },

      get skillDetailTotalPages() {
          return Math.max(1, Math.ceil((this.selectedClassSkills || []).length / Math.max(1, this.skillDetailPageSize)));
      },

      // ════════════════════════════════════════
      // Multi-select bulk delete (Suggestions tab)
      // ════════════════════════════════════════
      get selectedSuggestionCount() {
          var n = 0;
          for (var k in this.selectedSuggestions) {
              if (this.selectedSuggestions[k]) n++;
          }
          return n;
      },

      isPageFullySelected() {
          var page = this.paginatedSuggestions;
          if (page.length === 0) return false;
          for (var i = 0; i < page.length; i++) {
              if (!this.selectedSuggestions[page[i]._key]) return false;
          }
          return true;
      },

      togglePageSelection(checked) {
          var page = this.paginatedSuggestions;
          for (var i = 0; i < page.length; i++) {
              if (checked) this.selectedSuggestions[page[i]._key] = true;
              else delete this.selectedSuggestions[page[i]._key];
          }
      },

      clearSuggestionSelection() {
          this.selectedSuggestions = {};
      },

      async deleteSelectedSuggestions() {
          var keys = Object.keys(this.selectedSuggestions).filter((k) => this.selectedSuggestions[k]);
          if (keys.length === 0) return;
          if (!confirm('Delete ' + keys.length + ' suggestion(s)? This cannot be undone.')) return;
          // Snapshot rows to delete by key — `allSuggestions` is rebuilt on each
          // reload so we resolve identity now.
          var keySet = {};
          keys.forEach(function (k) {
              keySet[k] = true;
          });
          var rows = this.allSuggestions.filter(function (r) {
              return keySet[r._key];
          });
          var ok = 0, fail = 0;
          for (var i = 0; i < rows.length; i++) {
              var s = rows[i];
              try {
                  await OpenFangAPI.delete('/api/evolve/suggestion', {
                      analysis_id: s._analysis.id,
                      kind: (s.kind || 'fix').toLowerCase(),
                      description: s.description || ''
                  });
                  ok++;
              } catch (_) {
                  fail++;
              }
          }
          if (fail === 0) OpenFangToast.success('Deleted ' + ok + ' suggestion(s)');
          else OpenFangToast.error('Deleted ' + ok + ', failed ' + fail);
          this.selectedSuggestions = {};
          await this.loadAnalyses();
      },

      // ════════════════════════════════════════
    // Evolution execution
    // ════════════════════════════════════════
    executingAll: false,

    async executeSuggestion(analysisId, suggestion) {
      // Optimistically mark local row; the SSE/poll updates take over once
      // the server confirms the queued entry.
      suggestion._executing = true;
      try {
        await OpenFangAPI.post('/api/evolve/execute', {
          analysis_id: analysisId,
          kind: (suggestion.kind || 'fix').toLowerCase(),
          target_skill: suggestion.target_skill || null,
          description: suggestion.description || '',
          priority: suggestion.priority || 0
        });
        // Seed the local queue so the progress card shows the new item even
        // if the SSE 'queued' event hasn't arrived yet.
        var key = (analysisId || '') + '|' + (suggestion.kind || '').toLowerCase() + '|' + (suggestion.description || '');
        var q = this.executeProgress.queue;
        var present = q.some(function(x) {
          return ((x.analysis_id || '') + '|' + (x.kind || '') + '|' + (x.description || '')) === key;
        });
        if (!present) {
          q.push({
            analysis_id: analysisId || null,
            kind: (suggestion.kind || '').toLowerCase(),
            description: suggestion.description || '',
            target_skill: suggestion.target_skill || null,
            status: 'queued',
            failure_reason: null,
            change_summary: null,
          });
          this.executeProgress.total = Math.max(this.executeProgress.total, q.length);
        }
        this.executeProgress.running = true;
        this._startExecuteStream();
        this._startExecutePolling();
      } catch (e) {
        suggestion._executing = false;
          var msg = e && e.message ? e.message : String(e);
          // OpenFangAPI surfaces HTTP status; detect 429 via the error string.
          if (/429|queue full|too many/i.test(msg)) {
              OpenFangToast.error('Evolve queue full — retry in ~30s.');
          } else {
              OpenFangToast.error('Evolution failed to queue: ' + msg);
          }
      }
    },

    async deleteSuggestion(analysisId, suggestion) {
      if (!confirm('Delete this suggestion? This cannot be undone.')) return;
      suggestion._deleting = true;
      try {
        await OpenFangAPI.delete('/api/evolve/suggestion', {
          analysis_id: analysisId,
          kind: (suggestion.kind || 'fix').toLowerCase(),
          description: suggestion.description || ''
        });
        OpenFangToast.success('Suggestion deleted');
        await this.loadAnalyses();
      } catch (e) {
        OpenFangToast.error('Delete failed: ' + (e.message || e));
      }
      suggestion._deleting = false;
    },

    async executeAllSuggestions(analysis) {
      this.executingAll = true;
      try {
        var data = await OpenFangAPI.post('/api/evolve/execute-all', {
          analysis_id: analysis.id
        });
        OpenFangToast.success('Queued ' + (data.queued || 0) + ' evolutions');
        this.executeProgress.running = true;
        // Refresh snapshot so the queue list is fully populated before SSE
        // starts firing item-level events.
        try {
          var s = await OpenFangAPI.get('/api/evolve/execute/status');
          if (s) this._applyExecuteSnapshot(s);
        } catch (_) {}
        this._startExecuteStream();
        this._startExecutePolling();
      } catch (e) {
        OpenFangToast.error('Batch evolution failed to queue: ' + (e.message || e));
      }
      this.executingAll = false;
    },

    // ════════════════════════════════════════
    // Skill delete / rollback
    // ════════════════════════════════════════
    async deleteSkill(skillId) {
      if (!confirm('Delete skill "' + skillId + '"? This cannot be undone.')) return;
      try {
        var data = await OpenFangAPI.delete('/api/evolve/skills/' + encodeURIComponent(skillId));
        OpenFangToast.success('Deleted: ' + (data.name || skillId));
        await Promise.all([this.loadSkillRecords(), this.loadStats()]);
        this.buildSkillClasses();
        this.selectedSkillClass = null;
      } catch (e) {
        OpenFangToast.error('Delete failed: ' + (e.message || e));
      }
    },

    async rollbackSkill(skillId) {
      if (!confirm('Rollback "' + skillId + '" to its parent version?')) return;
      try {
        var data = await OpenFangAPI.post('/api/evolve/skills/' + encodeURIComponent(skillId) + '/rollback', {});
        OpenFangToast.success('Rolled back. Reactivated: ' + (data.reactivated_parents || []).join(', '));
        await Promise.all([this.loadSkillRecords(), this.loadStats()]);
        this.buildSkillClasses();
        this.selectedSkillClass = null;
      } catch (e) {
        OpenFangToast.error('Rollback failed: ' + (e.message || e));
      }
    },

    // ════════════════════════════════════════
    // Skill class grouping
    // ════════════════════════════════════════
    extractBaseName(skillId) {
      // Format: {name}__v{gen}_{uuid8} or {name}__imp_{uuid8}
      var m = skillId.match(/^(.+?)__(?:v\d+_|imp_)/);
      return m ? m[1] : skillId;
    },

    computeScore(s) {
      if (!s || s.total_selections === 0) return 0;
      var effective = s.total_completions / s.total_selections;
      return Math.round(effective * 1000) / 10;
    },

    buildSkillClasses() {
      var groups = {};
      var self = this;
      this.skillRecords.forEach(function(s) {
        // Group by skill name (preferred) or fall back to skill_id prefix.
        var base = s.name || self.extractBaseName(s.skill_id);
        if (!groups[base]) groups[base] = [];
        groups[base].push(s);
      });
      var classes = [];
      Object.keys(groups).forEach(function(name) {
        var skills = groups[name];
        var activeCount = 0, totalSel = 0, totalApplied = 0, totalComp = 0, totalFallback = 0;
        var bestScore = 0, scoreSum = 0, latestUpdate = null;
        var allTags = {}, allOrigins = {};
        var representative = null;

        skills.forEach(function(s) {
          if (s.is_active) activeCount++;
          totalSel += s.total_selections || 0;
          totalApplied += s.total_applied || 0;
          totalComp += s.total_completions || 0;
          totalFallback += s.total_fallbacks || 0;
          var sc = self.computeScore(s);
          if (sc > bestScore) bestScore = sc;
          scoreSum += sc;
          if (s.tags) s.tags.forEach(function(t) { allTags[t] = true; });
          if (s.lineage && s.lineage.origin) allOrigins[s.lineage.origin] = true;
          var upd = s.last_updated ? new Date(s.last_updated) : null;
          if (upd && (!latestUpdate || upd > latestUpdate)) latestUpdate = upd;

          // Representative: prefer active, higher gen, higher score
          if (!representative) { representative = s; return; }
          if (s.is_active && !representative.is_active) { representative = s; return; }
          if (s.is_active === representative.is_active) {
            var sGen = s.lineage ? s.lineage.generation : 0;
            var rGen = representative.lineage ? representative.lineage.generation : 0;
            if (sGen > rGen) { representative = s; return; }
            if (sGen === rGen && self.computeScore(s) > self.computeScore(representative)) representative = s;
          }
        });

        classes.push({
          name: name,
          skills: skills,
          representative: representative,
          versionCount: skills.length,
          activeCount: activeCount,
          bestScore: bestScore,
          avgScore: skills.length > 0 ? Math.round(scoreSum / skills.length * 10) / 10 : 0,
          totalSelections: totalSel,
          totalApplied: totalApplied,
          totalCompletions: totalComp,
          totalFallbacks: totalFallback,
          tags: Object.keys(allTags),
          origins: Object.keys(allOrigins),
          category: representative ? representative.category : '',
          description: representative ? representative.description : '',
          latestUpdate: latestUpdate
        });
      });
      this.skillClasses = classes;
    },

    get allTags() {
      var tags = {};
      this.skillRecords.forEach(function(s) {
        if (s.tags) s.tags.forEach(function(t) { tags[t] = true; });
      });
      return Object.keys(tags).sort();
    },

    get allOrigins() {
      var origins = {};
      this.skillRecords.forEach(function(s) {
        if (s.lineage && s.lineage.origin) origins[s.lineage.origin] = true;
      });
      return Object.keys(origins).sort();
    },

    get filteredSkillClasses() {
      var self = this;
      var result = this.skillClasses.slice();

      // Search filter
      if (this.skillSearch) {
        var q = this.skillSearch.toLowerCase();
        result = result.filter(function(c) {
          return c.name.toLowerCase().indexOf(q) >= 0 ||
            c.description.toLowerCase().indexOf(q) >= 0 ||
            c.tags.some(function(t) { return t.toLowerCase().indexOf(q) >= 0; }) ||
            c.category.toLowerCase().indexOf(q) >= 0;
        });
      }

      // Origin filter
      if (this.skillOriginFilter) {
        var of = this.skillOriginFilter;
        result = result.filter(function(c) { return c.origins.indexOf(of) >= 0; });
      }

      // Tag filter
      if (this.skillTagFilter) {
        var tf = this.skillTagFilter;
        result = result.filter(function(c) { return c.tags.indexOf(tf) >= 0; });
      }

      // Sort
      if (this.skillSort === 'score') {
        result.sort(function(a, b) { return b.bestScore - a.bestScore || b.totalSelections - a.totalSelections; });
      } else if (this.skillSort === 'updated') {
        result.sort(function(a, b) { return (b.latestUpdate || 0) - (a.latestUpdate || 0); });
      } else if (this.skillSort === 'name') {
        result.sort(function(a, b) { return a.name.localeCompare(b.name); });
      }
      return result;
    },

    get skillLibraryStats() {
      var total = this.skillClasses.length;
      var active = 0, scoreSum = 0, selSum = 0;
      this.skillClasses.forEach(function(c) {
        active += c.activeCount;
        scoreSum += c.bestScore;
        selSum += c.totalSelections;
      });
      return {
        classes: total,
        activeVersions: active,
        avgScore: total > 0 ? (scoreSum / total).toFixed(1) : '0',
        totalSelections: selSum
      };
    },

    // ════════════════════════════════════════
    // Skill detail + lineage graph
    // ════════════════════════════════════════
    navigateToSkillClass(className) {
      this.selectedClassName = className;
      var cls = this.skillClasses.find(function(c) { return c.name === className; });
      this.selectedClassSkills = cls ? cls.skills : [];
        this.skillDetailPage = 1;
      this.evolutionView = 'skill-detail';
      this.buildLineageGraph();
      var self = this;
      this.$nextTick(function() { self.renderGraph(); });
    },

    get selectedClass() {
      var n = this.selectedClassName;
      return this.skillClasses.find(function(c) { return c.name === n; }) || null;
    },

    buildLineageGraph() {
      var skills = this.selectedClassSkills;
      var nodes = [];
      var edges = [];
      var idMap = {};

      skills.forEach(function(s, i) {
        idMap[s.skill_id] = i;
        var gen = s.lineage ? s.lineage.generation : 0;
        nodes.push({
          id: s.skill_id,
          skill: s,
          gen: gen,
          x: 0, y: 0, vx: 0, vy: 0
        });
      });

      skills.forEach(function(s) {
        if (s.lineage && s.lineage.parent_skill_ids) {
          s.lineage.parent_skill_ids.forEach(function(pid) {
            if (idMap[pid] !== undefined) {
              edges.push({ source: pid, target: s.skill_id });
            }
          });
        }
      });

      // Initial positions: spread by generation
      var genGroups = {};
      nodes.forEach(function(n) {
        if (!genGroups[n.gen]) genGroups[n.gen] = [];
        genGroups[n.gen].push(n);
      });
      Object.keys(genGroups).forEach(function(gen) {
        var group = genGroups[gen];
        var y = parseInt(gen) * 100 + 50;
        group.forEach(function(n, i) {
          n.x = (i - (group.length - 1) / 2) * 100 + 300;
          n.y = y;
        });
      });

      // Simple force simulation (80 iterations)
      for (var iter = 0; iter < 80; iter++) {
        // Repulsion
        for (var i = 0; i < nodes.length; i++) {
          for (var j = i + 1; j < nodes.length; j++) {
            var dx = nodes[j].x - nodes[i].x;
            var dy = nodes[j].y - nodes[i].y;
            var dist = Math.sqrt(dx * dx + dy * dy) || 1;
            var force = -120 / (dist * dist);
            var fx = force * dx / dist;
            var fy = force * dy / dist;
            nodes[i].vx -= fx; nodes[i].vy -= fy;
            nodes[j].vx += fx; nodes[j].vy += fy;
          }
        }
        // Springs (edges)
        edges.forEach(function(e) {
          var si = idMap[e.source], ti = idMap[e.target];
          if (si === undefined || ti === undefined) return;
          var s = nodes[si], t = nodes[ti];
          var dx = t.x - s.x, dy = t.y - s.y;
          var dist = Math.sqrt(dx * dx + dy * dy) || 1;
          var force = (dist - 80) * 0.05;
          var fx = force * dx / dist, fy = force * dy / dist;
          s.vx += fx; s.vy += fy;
          t.vx -= fx; t.vy -= fy;
        });
        // Y gravity toward generation row
        nodes.forEach(function(n) {
          var targetY = n.gen * 100 + 50;
          n.vy += (targetY - n.y) * 0.1;
        });
        // Center gravity
        nodes.forEach(function(n) {
          n.vx += (300 - n.x) * 0.01;
        });
        // Apply velocity with damping
        var damping = 0.6;
        nodes.forEach(function(n) {
          n.x += n.vx * damping;
          n.y += n.vy * damping;
          n.vx *= 0.5;
          n.vy *= 0.5;
        });
      }

      this.graphNodes = nodes;
      this.graphEdges = edges;
    },

    renderGraph() {
      var canvas = document.getElementById('evo-lineage-canvas');
      if (!canvas) return;
      var ctx = canvas.getContext('2d');
      this.graphCanvas = canvas;
      this.graphCtx = ctx;

      // Fit to container
      var container = canvas.parentElement;
      canvas.width = container.clientWidth;
      canvas.height = Math.max(300, (this.maxGen() + 1) * 100 + 60);

      // Normalize positions to fit canvas
      var nodes = this.graphNodes;
      if (nodes.length === 0) return;
      var minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
      nodes.forEach(function(n) {
        if (n.x < minX) minX = n.x;
        if (n.x > maxX) maxX = n.x;
        if (n.y < minY) minY = n.y;
        if (n.y > maxY) maxY = n.y;
      });
      var rangeX = maxX - minX || 1;
      var rangeY = maxY - minY || 1;
      var padX = 60, padY = 40;
      var scaleX = (canvas.width - padX * 2) / rangeX;
      var scaleY = (canvas.height - padY * 2) / rangeY;
      var scale = Math.min(scaleX, scaleY, 1.5);

      var positions = [];
      var self = this;
      nodes.forEach(function(n) {
        positions.push({
          x: padX + (n.x - minX) * scale,
          y: padY + (n.y - minY) * scale,
          node: n
        });
      });
      this.graphPositions = positions;

      this.drawGraph(ctx, canvas.width, canvas.height, positions);
    },

    maxGen() {
      var max = 0;
      this.graphNodes.forEach(function(n) { if (n.gen > max) max = n.gen; });
      return max;
    },

    drawGraph(ctx, w, h, positions) {
      var self = this;
      var idToPos = {};
      positions.forEach(function(p) { idToPos[p.node.id] = p; });

      ctx.clearRect(0, 0, w, h);

      // Draw edges
      this.graphEdges.forEach(function(e) {
        var sp = idToPos[e.source], tp = idToPos[e.target];
        if (!sp || !tp) return;
        ctx.beginPath();
        var mx = (sp.x + tp.x) / 2;
        var my = (sp.y + tp.y) / 2;
        ctx.moveTo(sp.x, sp.y);
        ctx.quadraticCurveTo(mx + 15, my, tp.x, tp.y);
        ctx.strokeStyle = 'rgba(150,140,120,0.4)';
        ctx.lineWidth = 1.5;
        ctx.stroke();
        // Arrowhead
        var angle = Math.atan2(tp.y - my, tp.x - mx);
        ctx.beginPath();
        ctx.moveTo(tp.x, tp.y);
        ctx.lineTo(tp.x - 8 * Math.cos(angle - 0.4), tp.y - 8 * Math.sin(angle - 0.4));
        ctx.lineTo(tp.x - 8 * Math.cos(angle + 0.4), tp.y - 8 * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fillStyle = 'rgba(150,140,120,0.5)';
        ctx.fill();
      });

      // Draw nodes
      positions.forEach(function(p) {
        var s = p.node.skill;
        var score = self.computeScore(s);
        var maxSel = 1;
        self.graphNodes.forEach(function(n) { if (n.skill.total_selections > maxSel) maxSel = n.skill.total_selections; });
        var sizeRatio = Math.max(0.3, Math.sqrt((s.total_selections || 1) / maxSel));
        var radius = 8 + sizeRatio * 14;

        // Color by score: red(0) -> yellow(50) -> green(100)
        var r, g, b;
        if (score <= 50) {
          r = 220; g = Math.round(80 + score * 2.8); b = 60;
        } else {
          r = Math.round(220 - (score - 50) * 3.2); g = 200; b = 60;
        }
        var color = 'rgb(' + r + ',' + g + ',' + b + ')';

        // Glow
        ctx.save();
        ctx.shadowColor = color;
        ctx.shadowBlur = self.graphHover === p.node.id ? 16 : 6;

        ctx.beginPath();
        ctx.arc(p.x, p.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = s.is_active ? '#fff' : 'rgba(255,255,255,0.3)';
        ctx.lineWidth = s.is_active ? 2.5 : 1;
        ctx.stroke();
        ctx.restore();

        // Active indicator (inner white dot)
        if (s.is_active) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
          ctx.fillStyle = '#fff';
          ctx.fill();
        }

        // Label
        var label = self.shortLabel(s.skill_id);
        ctx.font = '10px ui-monospace, monospace';
        ctx.textAlign = 'center';
        ctx.fillStyle = 'var(--text-primary, #ccc)';
        ctx.fillText(label, p.x, p.y + radius + 12);
      });
    },

    shortLabel(skillId) {
      // Extract version part: v{gen} or imp
      var m = skillId.match(/__(.+)$/); // safe: internal skillId, anchored to '__' separator, result truncated to 10 chars
      return m ? m[1].substring(0, 10) : skillId.substring(0, 10);
    },

    handleGraphClick(event) {
      var canvas = this.graphCanvas;
      if (!canvas) return;
      var rect = canvas.getBoundingClientRect();
      var mx = event.clientX - rect.left;
      var my = event.clientY - rect.top;
      var self = this;

      var hit = null;
      this.graphPositions.forEach(function(p) {
        var s = p.node.skill;
        var maxSel = 1;
        self.graphNodes.forEach(function(n) { if (n.skill.total_selections > maxSel) maxSel = n.skill.total_selections; });
        var sizeRatio = Math.max(0.3, Math.sqrt((s.total_selections || 1) / maxSel));
        var radius = 8 + sizeRatio * 14;
        var dx = mx - p.x, dy = my - p.y;
        if (dx * dx + dy * dy <= radius * radius) hit = p.node;
      });

      if (hit) this.openVersionDrawer(hit.skill);
    },

    handleGraphMove(event) {
      var canvas = this.graphCanvas;
      if (!canvas) return;
      var rect = canvas.getBoundingClientRect();
      var mx = event.clientX - rect.left;
      var my = event.clientY - rect.top;
      var self = this;
      var oldHover = this.graphHover;
      this.graphHover = null;

      this.graphPositions.forEach(function(p) {
        var s = p.node.skill;
        var maxSel = 1;
        self.graphNodes.forEach(function(n) { if (n.skill.total_selections > maxSel) maxSel = n.skill.total_selections; });
        var sizeRatio = Math.max(0.3, Math.sqrt((s.total_selections || 1) / maxSel));
        var radius = 8 + sizeRatio * 14;
        var dx = mx - p.x, dy = my - p.y;
        if (dx * dx + dy * dy <= radius * radius) self.graphHover = p.node.id;
      });

      canvas.style.cursor = this.graphHover ? 'pointer' : 'default';
      if (this.graphHover !== oldHover && this.graphCtx) {
        this.drawGraph(this.graphCtx, canvas.width, canvas.height, this.graphPositions);
      }
    },

    // ════════════════════════════════════════
    // Version drawer
    // ════════════════════════════════════════
    openVersionDrawer(skill) {
      this.drawerSkill = skill;
      this.drawerSourceTab = 0;
      this.drawerDiffFiles = skill.lineage && skill.lineage.content_diff ? this.parseDiff(skill.lineage.content_diff) : [];
      this.showVersionDrawer = true;
      document.body.style.overflow = 'hidden';
    },

    closeVersionDrawer() {
      this.showVersionDrawer = false;
      this.drawerSkill = null;
      this.drawerDiffFiles = [];
      document.body.style.overflow = '';
    },

    handleDrawerKeydown(event) {
      if (event.key === 'Escape') this.closeVersionDrawer();
    },

    get drawerScore() {
      return this.drawerSkill ? this.computeScore(this.drawerSkill) : 0;
    },
    drawerRate(field) {
      var s = this.drawerSkill;
      if (!s) return 0;
      if (field === 'effective') return s.total_selections > 0 ? s.total_completions / s.total_selections : 0;
      if (field === 'completion') return s.total_applied > 0 ? s.total_completions / s.total_applied : 0;
      if (field === 'applied') return s.total_selections > 0 ? s.total_applied / s.total_selections : 0;
      if (field === 'fallback') return s.total_selections > 0 ? s.total_fallbacks / s.total_selections : 0;
      return 0;
    },
    drawerRatePct(field) {
      return (this.drawerRate(field) * 100).toFixed(0) + '%';
    },

    get drawerSourceFiles() {
      var s = this.drawerSkill;
      if (!s || !s.lineage || !s.lineage.content_snapshot) return [];
      return Object.keys(s.lineage.content_snapshot);
    },
    drawerSourceContent(idx) {
      var files = this.drawerSourceFiles;
      if (idx >= files.length) return '';
      return this.drawerSkill.lineage.content_snapshot[files[idx]] || '';
    },

    // ════════════════════════════════════════
    // Diff parser
    // ════════════════════════════════════════
    parseDiff(diffText) {
      if (!diffText || diffText.length > 256000) return [];
      var files = [];
      var currentFile = null;
      var currentHunk = null;
      var lines = diffText.split('\n');

      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];

        // File header
        if (line.indexOf('--- ') === 0 && i + 1 < lines.length && lines[i + 1].indexOf('+++ ') === 0) {
          var newPath = lines[i + 1].substring(4).replace(/^[ab]\//, '');
          currentFile = { path: newPath, hunks: [] };
          files.push(currentFile);
          i++; // skip +++ line
          continue;
        }

        // Hunk header
        if (line.indexOf('@@ ') === 0) {
          currentHunk = { header: line, lines: [] };
          if (currentFile) currentFile.hunks.push(currentHunk);
          continue;
        }

        // Diff lines
        if (currentHunk) {
          if (line.indexOf('+') === 0 && line.indexOf('+++') !== 0) {
            currentHunk.lines.push({ type: 'add', text: line.substring(1) });
          } else if (line.indexOf('-') === 0 && line.indexOf('---') !== 0) {
            currentHunk.lines.push({ type: 'del', text: line.substring(1) });
          } else if (line.indexOf(' ') === 0 || line === '') {
            currentHunk.lines.push({ type: 'ctx', text: line.substring(1) || '' });
          }
        }
      }

      // If no file headers found, create a single virtual file
      if (files.length === 0 && diffText.trim()) {
        currentFile = { path: 'SKILL.md', hunks: [] };
        currentHunk = { header: '', lines: [] };
        lines.forEach(function(line) {
          if (line.indexOf('+') === 0) currentHunk.lines.push({ type: 'add', text: line.substring(1) });
          else if (line.indexOf('-') === 0) currentHunk.lines.push({ type: 'del', text: line.substring(1) });
          else if (line.indexOf('@@ ') === 0) { /* skip hunk headers */ }
          else currentHunk.lines.push({ type: 'ctx', text: line });
        });
        if (currentHunk.lines.length > 0) currentFile.hunks.push(currentHunk);
        if (currentFile.hunks.length > 0) files.push(currentFile);
      }

      return files;
    },

    // ════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════
    fmtTime(ts) {
      if (!ts) return '-';
      var d = new Date(ts);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },
    fmtTimeShort(ts) {
      if (!ts) return '-';
      var d = new Date(ts);
      return d.toLocaleDateString();
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
    originClass(o) {
      if (o === 'imported') return 'badge-info';
      if (o === 'captured') return 'badge-success';
      if (o === 'derived') return 'badge-warning';
      if (o === 'fixed') return 'badge-danger';
      return 'badge-dim';
    },
    shortId(id) {
      return id ? id.substring(0, 8) : '-';
    },
    scoreColor(score) {
      if (score >= 70) return 'var(--color-success, #22c55e)';
      if (score >= 40) return 'var(--color-warning, #eab308)';
      return 'var(--color-danger, #ef4444)';
    },
    ratePctText(numerator, denominator) {
      if (!denominator || denominator === 0) return '-';
      return ((numerator / denominator) * 100).toFixed(0) + '%';
    },
    skillAppliedRate(s) {
      return s.total_selections > 0 ? ((s.total_applied / s.total_selections) * 100).toFixed(0) + '%' : '-';
    },
    skillCompletionRate(s) {
      return s.total_applied > 0 ? ((s.total_completions / s.total_applied) * 100).toFixed(0) + '%' : '-';
    },
    truncate(text, len) {
      if (!text) return '';
      return text.length > len ? text.substring(0, len) + '...' : text;
    }
  };
}
