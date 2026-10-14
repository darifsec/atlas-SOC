const tls = require('tls');
const net = require('net');
const { parseStringPromise } = require('xml2js');

// Safe nested-property getter (works on old Node versions too)
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
 * Minimal GMP client. One fresh connection per call:
 * connect -> authenticate -> run commands -> close.
 * GVM_USE_TLS=false is for the plain-TCP socat gmp-proxy.
 */
class GvmClient {
  constructor(cfg) {
    this.host = cfg.host;
    this.port = cfg.port;
    this.user = cfg.user;
    this.pass = cfg.pass;
    this.rejectUnauthorized = cfg.tlsRejectUnauthorized !== false;
    this.useTls = cfg.useTls !== false;
    this._cache = {};
  }

  _escape(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  _run(commands) {
    return new Promise((resolve, reject) => {
      const self = this;
      let settled = false;
      function ok(v) { if (!settled) { settled = true; resolve(v); } }
      function bad(e) { if (!settled) { settled = true; reject(e); } }

      const socket = this.useTls
        ? tls.connect(
            { host: this.host, port: this.port, rejectUnauthorized: this.rejectUnauthorized },
            () => sendCurrent()
          )
        : net.connect({ host: this.host, port: this.port }, () => sendCurrent());

      socket.setTimeout(20000);
      socket.on('timeout', () => {
        socket.destroy();
        bad(new Error(
          'GVM timed out talking to ' + self.host + ':' + self.port +
          ' over ' + (self.useTls ? 'TLS' : 'plain TCP')
        ));
      });
      socket.on('error', (err) => bad(new Error('GVM connection error: ' + err.message)));
      socket.on('close', () => bad(new Error('GVM connection closed before a reply')));

      const authXml =
        '<authenticate><credentials>' +
        '<username>' + this._escape(this.user) + '</username>' +
        '<password>' + this._escape(this.pass) + '</password>' +
        '</credentials></authenticate>';

      const queue = [{ xml: authXml, rootTag: 'authenticate_response' }].concat(commands);
      const results = [];
      let buffer = '';
      let current = null;
      let busy = false;

      function sendCurrent() {
        current = queue.shift();
        buffer = '';
        socket.write(current.xml);
      }

      socket.on('data', async (chunk) => {
        if (busy || !current) return;
        buffer += chunk.toString('utf8');

        // Reply is complete when we see a self-closing tag OR a closing tag
        const done = new RegExp(
          '<' + current.rootTag + '\\b[^>]*/>|</' + current.rootTag + '>'
        );
        if (!done.test(buffer)) return;

        busy = true;
        try {
          const parsed = await parseStringPromise(buffer, { explicitArray: false, trim: true });
          const root = parsed[current.rootTag];
          const status = get(root, '$.status', null);
          if (status && status.charAt(0) !== '2') {
            throw new Error(
              'GVM rejected ' + current.rootTag.replace('_response', '') + ': ' +
              get(root, '$.status_text', status)
            );
          }
          results.push(parsed);

          if (queue.length === 0) {
            ok(results.slice(1)); // drop authenticate_response
            socket.end();
          } else {
            busy = false;
            sendCurrent();
          }
        } catch (err) {
          bad(err);
          socket.destroy();
        }
      });
    });
  }

  // ---- lookups by name (built-in IDs differ between installs) ----

  async _findId(xml, rootTag, listKey, wantedName) {
    const results = await this._run([{ xml: xml, rootTag: rootTag }]);
    let items = get(results[0], rootTag + '.' + listKey, []);
    if (!Array.isArray(items)) items = items ? [items] : [];
    if (!items.length) throw new Error('GVM returned no ' + listKey + ' entries');
    const want = wantedName.toLowerCase();
    const match = items.find(
      (i) => typeof i.name === 'string' && i.name.toLowerCase() === want
    );
    return get(match || items[0], '$.id', null);
  }

  async _cached(key, fn) {
    if (!this._cache[key]) this._cache[key] = await fn();
    return this._cache[key];
  }

  _portListId() {
    return this._cached('portList', () =>
      this._findId('<get_port_lists/>', 'get_port_lists_response', 'port_list', 'All IANA assigned TCP'));
  }

  _scannerId() {
    return this._cached('scanner', () =>
      this._findId('<get_scanners/>', 'get_scanners_response', 'scanner', 'OpenVAS Default'));
  }

  _defaultConfigId() {
    return this._cached('config', () =>
      this._findId('<get_configs/>', 'get_configs_response', 'config', 'Full and fast'));
  }

  // ---- tasks ----

  async startTask(taskId) {
    const xml = '<start_task task_id="' + this._escape(taskId) + '"/>';
    const results = await this._run([{ xml: xml, rootTag: 'start_task_response' }]);
    const reportId = get(results[0], 'start_task_response.report_id', null);
    return { started: true, reportId: reportId };
  }

  async getTaskStatus(taskId) {
    const xml = '<get_tasks task_id="' + this._escape(taskId) + '" details="0"/>';
    const results = await this._run([{ xml: xml, rootTag: 'get_tasks_response' }]);
    const task = get(results[0], 'get_tasks_response.task', null);
    if (!task) return { found: false };

    const progressRaw = task.progress;
    return {
      found: true,
      id: get(task, '$.id', null),
      name: task.name,
      status: task.status,
      progress: progressRaw != null ? Number(progressRaw) : null,
      lastReportId: get(task, 'last_report.report.$.id', null)
    };
  }

  async createTask(name, configId, targetId) {
    const cfg = configId || (await this._defaultConfigId());
    const scannerId = await this._scannerId();
    const xml =
      '<create_task><name>' + this._escape(name) + '</name>' +
      '<config id="' + this._escape(cfg) + '"/>' +
      '<target id="' + this._escape(targetId) + '"/>' +
      '<scanner id="' + this._escape(scannerId) + '"/></create_task>';
    const results = await this._run([{ xml: xml, rootTag: 'create_task_response' }]);
    const id = get(results[0], 'create_task_response.$.id', null);
    if (!id) throw new Error('GVM did not return a task id');
    return { taskId: id };
  }

  async deleteTask(taskId) {
    const xml = '<delete_task task_id="' + this._escape(taskId) + '" ultimate="1"/>';
    await this._run([{ xml: xml, rootTag: 'delete_task_response' }]);
    return true;
  }

  // ---- targets ----

  async createTarget(name, hosts) {
    const portListId = await this._portListId();
    const xml =
      '<create_target><name>' + this._escape(name) + '</name>' +
      '<hosts>' + this._escape(hosts) + '</hosts>' +
      '<port_list id="' + this._escape(portListId) + '"/></create_target>';
    const results = await this._run([{ xml: xml, rootTag: 'create_target_response' }]);
    const id = get(results[0], 'create_target_response.$.id', null);
    if (!id) throw new Error('GVM did not return a target id');
    return { targetId: id };
  }

  async deleteTarget(targetId) {
    const xml = '<delete_target target_id="' + this._escape(targetId) + '" ultimate="1"/>';
    await this._run([{ xml: xml, rootTag: 'delete_target_response' }]);
    return true;
  }

  // ---- scan configs (for a dropdown in the UI) ----

  async getConfigs() {
    const results = await this._run([{ xml: '<get_configs/>', rootTag: 'get_configs_response' }]);
    let configs = get(results[0], 'get_configs_response.config', []);
    if (!Array.isArray(configs)) configs = configs ? [configs] : [];
    return configs.map((c) => ({ id: get(c, '$.id', null), name: c.name }));
  }
}

module.exports = { GvmClient };
