const axios = require('axios');
const https = require('https');

// Safe nested-property getter, since this project targets older Node
// versions too (no optional chaining / nullish coalescing).
function get(obj, path, def) {
  var parts = path.split('.');
  var cur = obj;
  for (var i = 0; i < parts.length; i++) {
    if (cur == null) return def;
    cur = cur[parts[i]];
  }
  return cur == null ? def : cur;
}

/**
 * Minimal client for the Wazuh indexer (OpenSearch), used to pull alerts
 * out of the wazuh-alerts-* index. This is NOT the Wazuh manager API
 * (port 55000) - that API manages agents/rules, it does not expose alerts.
 */
class WazuhClient {
  constructor(cfg) {
    this.host = cfg.host;
    this.port = cfg.port;
    this.user = cfg.user;
    this.pass = cfg.pass;
    this.index = cfg.index || 'wazuh-alerts-*';
    this.baseURL = `https://${this.host}:${this.port}`;

    this.http = axios.create({
      baseURL: this.baseURL,
      auth: { username: this.user, password: this.pass },
      httpsAgent: new https.Agent({
        rejectUnauthorized: cfg.tlsRejectUnauthorized !== false
      }),
      timeout: 10000
    });
  }

  severityBand(level) {
    // Common Wazuh convention. Tune these thresholds in your own deployment
    // if your ruleset maps severity differently.
    if (level >= 12) return 'critical';
    if (level >= 10) return 'high';
    if (level >= 7) return 'medium';
    return 'low';
  }

  /**
   * Fetch recent alerts with rule.level >= minLevel, newest first.
   */
  async getAlerts(opts) {
    opts = opts || {};
    const minLevel = opts.minLevel != null ? opts.minLevel : 7;
    const limit = opts.limit != null ? opts.limit : 100;

    const body = {
      size: limit,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: {
        range: { 'rule.level': { gte: minLevel } }
      },
      _source: [
        '@timestamp',
        'rule.id',
        'rule.level',
        'rule.description',
        'rule.groups',
        'agent.id',
        'agent.name',
        'manager.name',
        'data',
        'full_log'
      ]
    };

    const res = await this.http.post(`/${this.index}/_search`, body);
    const hits = get(res, 'data.hits.hits', []);

    return hits.map((h) => {
      const s = h._source || {};
      const level = get(s, 'rule.level', 0);
      return {
        id: h._id,
        timestamp: s['@timestamp'],
        level,
        severity: this.severityBand(level),
        description: get(s, 'rule.description', '(no description)'),
        ruleId: get(s, 'rule.id', null),
        groups: get(s, 'rule.groups', []),
        agent: get(s, 'agent.name', null) || get(s, 'agent.id', 'unknown'),
        manager: get(s, 'manager.name', null),
        fullLog: s.full_log
      };
    });
  }

  /**
   * Quick connectivity/auth check used by /api/health.
   */
  async ping() {
    const res = await this.http.get('/');
    return { ok: true, cluster: get(res, 'data.cluster_name', null) };
  }
}

module.exports = { WazuhClient };
