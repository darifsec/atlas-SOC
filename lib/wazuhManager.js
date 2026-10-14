const axios = require('axios');
const https = require('https');

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
 * Client for the Wazuh MANAGER REST API (default port 55000) - different
 * service from the indexer (lib/wazuh.js, port 9200). This is what can
 * register/remove agents.
 *
 * Registering an agent here only creates its entry on the manager and
 * returns an enrollment key. It does NOT install or start the Wazuh
 * agent service on the target machine - that still has to be run on the
 * device itself (there's no way to push software onto a box this
 * dashboard doesn't already have access to).
 */
class WazuhManagerClient {
  constructor(cfg) {
    this.host = cfg.host;
    this.port = cfg.port;
    this.user = cfg.user;
    this.pass = cfg.pass;
    this.baseURL = `https://${this.host}:${this.port}`;
    this.http = axios.create({
      baseURL: this.baseURL,
      httpsAgent: new https.Agent({ rejectUnauthorized: cfg.tlsRejectUnauthorized !== false }),
      timeout: 10000
    });
    this._token = null;
    this._tokenExpiresAt = 0;
  }

  async _authenticate() {
    const res = await this.http.post('/security/user/authenticate', null, {
      auth: { username: this.user, password: this.pass }
    });
    const token = get(res, 'data.data.token', null);
    if (!token) throw new Error('Wazuh manager authentication did not return a token');
    this._token = token;
    // Default token lifetime is 900s - refresh a bit early.
    this._tokenExpiresAt = Date.now() + 14 * 60 * 1000;
    return token;
  }

  async _authedRequest(method, url, opts) {
    opts = opts || {};
    if (!this._token || Date.now() >= this._tokenExpiresAt) {
      await this._authenticate();
    }
    const withAuth = (token) =>
      Object.assign({ method, url, headers: { Authorization: `Bearer ${token}` } }, opts);
    try {
      return await this.http.request(withAuth(this._token));
    } catch (err) {
      const status = get(err, 'response.status', null);
      if (status === 401) {
        await this._authenticate();
        return this.http.request(withAuth(this._token));
      }
      throw err;
    }
  }

  /**
   * Registers a new agent (quick method). Returns the new agent's id and
   * enrollment key.
   */
  async addAgent(name, ip) {
    const res = await this._authedRequest('post', '/agents', {
      data: { name, ip: ip || 'any' }
    });
    const data = get(res, 'data.data', null);
    if (!data || !data.id) throw new Error('Wazuh manager did not return an agent id');
    return { agentId: data.id, agentKey: data.key || null };
  }

  async getAgentStatus(agentId) {
    const res = await this._authedRequest('get', '/agents', {
      params: { agents_list: agentId }
    });
    const items = get(res, 'data.data.affected_items', []);
    if (!items.length) return null;
    return { id: items[0].id, status: items[0].status, name: items[0].name };
  }

  async removeAgent(agentId) {
    await this._authedRequest('delete', '/agents', {
      params: { agents_list: agentId, status: 'all' }
    });
    return true;
  }
}

module.exports = { WazuhManagerClient };
