function evolutionPage() {
  return {
    // ── Sub-view routing ──
    evolutionView: 'overview',  // 'overview' | 'skills' | 'skill-detail' | 'suggestions'

    // ── Existing state ──
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
    triggerRunning: false,

    // ── Skills library state ──
    skillSearch: '',
    skillSort: 'score',
    skillOriginFilter: '',
    skillTagFilter: '',
    skillClasses: [],

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
      this.loading = true;
      this.loadError = '';
      try {
        await Promise.all([this.loadConfig(), this.loadStats(), this.loadAnalyses(), this.loadModelOptions(), this.loadAgent(), this.loadSkillRecords()]);
        this.buildSkillClasses();
      } catch (e) {
        this.loadError = e.message || 'Failed to load evolution data.';
      }
      this.loading = false;
    },

    // ════════════════════════════════════════
    // API loaders (unchanged)
    // ════════════════════════════════════════
    async loadConfig() {
      var data = await OpenFangAPI.get('/api/evolve/config');
      if (data) this.config = data;
    },
    async saveConfig() {
      this.saving = true;
      try {
        var body = { enabled: this.config.enabled, provider: this.config.provider, model: this.config.model, batch_size: parseInt(this.config.batch_size) || 20 };
        if (this.config.api_key) body.api_key = this.config.api_key;
        if (this.config.base_url) body.base_url = this.config.base_url;
        await OpenFangAPI.put('/api/evolve/config', body);
        OpenFangToast.success('Configuration saved');
      } catch (e) { OpenFangToast.error('Failed to save: ' + (e.message || e)); }
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
      if (!currentValid) this.config.model = filtered[0].id;
    },
    async loadAgent() {
      try {
        var data = await OpenFangAPI.get('/api/evolve/agent');
        this.analyzerAgentId = data.agent_id || null;
      } catch (e) { this.analyzerAgentId = null; }
    },
    async loadAnalyses() {
      var data = await OpenFangAPI.get('/api/evolve/analyses?limit=50');
      if (data && data.analyses) {
        data.analyses.forEach(function(a) {
          (a.evolution_suggestions || []).forEach(function(s) {
            s._executing = false;
            s._deleting = false;
          });
        });
        this.analyses = data.analyses;
      }
    },
    async runAnalysis() {
      this.running = true;
      this.lastRunResult = null;
      try {
        var data = await OpenFangAPI.post('/api/evolve/run', {});
        this.lastRunResult = data;
        OpenFangToast.success('Analyzed ' + (data.analyzed || 0) + ' sessions');
        await Promise.all([this.loadStats(), this.loadAnalyses(), this.loadAgent(), this.loadSkillRecords()]);
        this.buildSkillClasses();
      } catch (e) { OpenFangToast.error('Analysis failed: ' + (e.message || e)); }
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
      var sort = this.suggestionsSort;
      var desc = sort.charAt(0) === '-';
      var field = desc ? sort.substring(1) : sort;
      list.sort(function(a, b) {
        var va = a[field] || 0, vb = b[field] || 0;
        if (va < vb) return desc ? 1 : -1;
        if (va > vb) return desc ? -1 : 1;
        return 0;
      });
      return list;
    },

    // ════════════════════════════════════════
    // Evolution execution
    // ════════════════════════════════════════
    executingAll: false,

    async executeSuggestion(analysisId, suggestion) {
      suggestion._executing = true;
      try {
        var data = await OpenFangAPI.post('/api/evolve/execute', {
          analysis_id: analysisId,
          kind: (suggestion.kind || 'fix').toLowerCase(),
          target_skill: suggestion.target_skill || null,
          description: suggestion.description || '',
          priority: suggestion.priority || 0
        });
        OpenFangToast.success('Evolution complete: ' + (data.change_summary || 'success'));
        await Promise.all([this.loadSkillRecords(), this.loadStats(), this.loadAnalyses()]);
        this.buildSkillClasses();
      } catch (e) {
        OpenFangToast.error('Evolution failed: ' + (e.message || e));
      }
      suggestion._executing = false;
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
        var msg = 'Executed ' + (data.succeeded || 0) + '/' + (data.executed || 0) + ' evolutions';
        if (data.failed > 0) msg += ' (' + data.failed + ' failed)';
        OpenFangToast.success(msg);
        await Promise.all([this.loadSkillRecords(), this.loadStats(), this.loadAnalyses()]);
        this.buildSkillClasses();
      } catch (e) {
        OpenFangToast.error('Batch evolution failed: ' + (e.message || e));
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
      var m = skillId.match(/__(.+)$/);
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
