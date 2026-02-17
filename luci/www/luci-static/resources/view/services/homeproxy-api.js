'use strict';
'require view';
'require form';
'require fs';
'require rpc';
'require poll';
'require ui';
'require uci';

const SERVICE_NAME = 'homeproxy-api';
const UCI_CONFIG = 'homeproxy-api';
const INIT_SCRIPT = '/etc/init.d/homeproxy-api';
const LOGREAD_BIN = '/sbin/logread';
const RC_LINK = '/etc/rc.d/S99homeproxy-api';

const FILES_TO_REMOVE_ORDERED = [
	'/usr/share/luci/menu.d/luci-app-homeproxy-api.json',
	'/www/luci-static/resources/view/services/homeproxy-api.js',
	'/usr/bin/homeproxy-api',
	'/etc/config/homeproxy-api',
	'/etc/init.d/homeproxy-api',
	'/usr/share/rpcd/acl.d/luci-app-homeproxy-api.json'
];

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

function getServiceRunning() {
	return L.resolveDefault(callServiceList(SERVICE_NAME), {}).then(function(res) {
		try {
			var svc = res[SERVICE_NAME];
			if (!svc || !svc.instances)
				return false;
			for (var key in svc.instances) {
				if (svc.instances[key] && svc.instances[key].running)
					return true;
			}
		} catch (e) {}
		return false;
	});
}

function getAutostartEnabled() {
	return L.resolveDefault(fs.stat(RC_LINK), null).then(function(st) {
		return !!st;
	});
}

function serviceStateText(running, autostart) {
	var runText = running
		? '<span style="color:green"><strong>' + _('RUNNING') + '</strong></span>'
		: '<span style="color:red"><strong>' + _('NOT RUNNING') + '</strong></span>';
	var autoText = autostart
		? '<span style="color:green"><strong>' + _('ENABLED') + '</strong></span>'
		: '<span style="color:red"><strong>' + _('DISABLED') + '</strong></span>';
	return _('<strong>Service:</strong> %s &nbsp;|&nbsp; <strong>Autostart:</strong> %s').format(runText, autoText);
}

function safeExec(path, args) {
	return L.resolveDefault(fs.exec(path, args), null);
}

function generateTokenHex(byteLen) {
	var bytes = [];
	var i, out = '';
	byteLen = byteLen || 24;

	if (window.crypto && window.crypto.getRandomValues) {
		var arr = new Uint8Array(byteLen);
		window.crypto.getRandomValues(arr);
		for (i = 0; i < arr.length; i++)
			bytes.push(arr[i]);
	} else {
		for (i = 0; i < byteLen; i++)
			bytes.push(Math.floor(Math.random() * 256));
	}

	for (i = 0; i < bytes.length; i++)
		out += ('0' + bytes[i].toString(16)).slice(-2);

	return out;
}

function removeFilesSequentially(paths) {
	var p = Promise.resolve();
	paths.forEach(function(path) {
		p = p.then(function() {
			return L.resolveDefault(fs.remove(path), null);
		});
	});
	return p;
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load(UCI_CONFIG),
			getAutostartEnabled()
		]);
	},

	handleSaveApply: function(ev, mode) {
		return this.handleSave(ev).then(function() {
			var autostart = uci.get(UCI_CONFIG, 'main', 'autostart');
			if (autostart == null || autostart === '')
				autostart = '1';

			return Promise.resolve()
				.then(function() {
					return safeExec(INIT_SCRIPT, [autostart === '1' ? 'enable' : 'disable']);
				})
				.then(function() {
					return safeExec(INIT_SCRIPT, ['reload']);
				})
				.then(function() {
					ui.changes.apply(mode === '0');
				});
		});
	},

	handleShowLogs: function() {
		return fs.exec(LOGREAD_BIN, ['-l', '200', '-e', SERVICE_NAME]).then(function(res) {
			var out = (res && res.stdout) ? res.stdout.trim() : '';
			ui.showModal(_('HomeProxy API Logs'), [
				E('p', {}, _('Showing last 200 log lines filtered by "%s".').format(SERVICE_NAME)),
				E('pre', {
					'style': 'max-height: 60vh; overflow: auto; white-space: pre-wrap; word-break: break-word; margin: 0;'
				}, out || _('Log is empty.')),
				E('div', { 'class': 'right' }, [
					E('button', { 'class': 'btn', 'click': ui.hideModal }, _('Close'))
				])
			]);
		}).catch(function(err) {
			ui.addNotification(null, E('p', {}, _('Failed to read logs: %s').format(err)));
		});
	},

	handleUninstall: function() {
		if (!window.confirm(_('This will remove HomeProxy API service, autostart, binary, config, ACL and LuCI page. Continue?')))
			return Promise.resolve();

		ui.showModal(_('Uninstalling'), [
			E('p', { 'class': 'spinning' }, _('Removing HomeProxy API components...'))
		]);

		return Promise.resolve()
			.then(function() { return safeExec(INIT_SCRIPT, ['stop']); })
			.then(function() { return safeExec(INIT_SCRIPT, ['disable']); })
			.then(function() { return removeFilesSequentially(FILES_TO_REMOVE_ORDERED); })
			.then(function() {
				ui.hideModal();
				ui.addNotification(null,
					E('p', {}, _('HomeProxy API was removed. Reloading Services page...')),
					'info');
				window.setTimeout(function() {
					window.location.href = L.url('admin', 'services');
				}, 1200);
			}).catch(function(err) {
				ui.hideModal();
				ui.addNotification(null, E('p', {}, _('Uninstall failed: %s').format(err)));
			});
	},

	render: function(data) {
		var m, s, o;
		var autostartCurrent = !!data[1];

		m = new form.Map(UCI_CONFIG, _('HomeProxy API'),
			_('Batch route-check API for HomeProxy/sing-box rules.'));

		s = m.section(form.TypedSection, '_runtime', _('Service Status'));
		s.anonymous = true;
		s.addremove = false;
		s.render = function() {
			poll.add(function() {
				return Promise.all([
					getServiceRunning(),
					getAutostartEnabled()
				]).then(function(res) {
					var el = document.getElementById('homeproxy-api-status');
					if (el)
						el.innerHTML = serviceStateText(res[0], res[1]);
				});
			});
			return E('div', { 'class': 'cbi-section' }, [
				E('p', { 'id': 'homeproxy-api-status' }, _('Collecting data...'))
			]);
		};

		s = m.section(form.NamedSection, 'main', 'main', _('Basic Settings'));
		s.anonymous = true;

		o = s.option(form.Flag, 'enabled', _('Enable service'));
		o.rmempty = false;
		o.default = o.enabled;

		o = s.option(form.Flag, 'autostart', _('Enable autostart'));
		o.rmempty = false;
		o.default = autostartCurrent ? o.enabled : o.disabled;
		o.cfgvalue = function() {
			return autostartCurrent ? '1' : '0';
		};
		o.description = _('Apply to synchronize init autostart state.');

		o = s.option(form.ListValue, 'mode', _('Working mode'));
		o.value('default', _('default (cached in RAM, faster)'));
		o.value('eco', _('eco (cold-run per request, lower RAM)'));
		o.default = 'default';
		o.rmempty = false;

		o = s.option(form.Value, 'port', _('HomeProxy API port'));
		o.datatype = 'port';
		o.placeholder = '7878';
		o.rmempty = true;
		o.description = _('If set, service listens on 0.0.0.0:<port>. If empty, legacy "listen" option is used.');

		o = s.option(form.Value, 'access_token', _('Access token'));
		o.placeholder = _('token is not used');
		o.rmempty = true;
		o.default = '';
		o.description = _('Leave empty to disable token auth for API requests.');
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			var node = form.Value.prototype.renderWidget.apply(this, arguments);
			var group = node.querySelector('.control-group') || node;
			var input = node.querySelector('input');
			var button;

			group.style.display = 'flex';
			group.style.alignItems = 'center';
			group.style.gap = '0.5rem';

			if (input) {
				input.style.flex = '1 1 auto';
			}

			button = E('button', {
				'class': 'cbi-button cbi-button-action',
				'type': 'button',
				'click': ui.createHandlerFn(this, function(ev) {
					var tokenInput = input || (ev && ev.target && ev.target.parentNode ? ev.target.parentNode.querySelector('input') : null);
					if (!tokenInput)
						return;
					tokenInput.value = generateTokenHex(24);
					tokenInput.dispatchEvent(new Event('input', { bubbles: true }));
					tokenInput.dispatchEvent(new Event('change', { bubbles: true }));
					tokenInput.focus();
				}, this.option)
			}, [_('Generate token')]);

			group.appendChild(button);
			return node;
		};

		s = m.section(form.NamedSection, 'main', 'main', _('Tools'));
		s.anonymous = true;

		o = s.option(form.Button, '_show_logs', _('Logs'));
		o.inputtitle = _('Show logs');
		o.inputstyle = 'action';
		o.onclick = ui.createHandlerFn(this, 'handleShowLogs');

		o = s.option(form.Button, '_uninstall', _('Uninstall'));
		o.inputtitle = _('Remove service + LuCI page');
		o.inputstyle = 'reset';
		o.onclick = ui.createHandlerFn(this, 'handleUninstall');
		o.description = _('This action removes HomeProxy API service files and this LuCI page.');

		return m.render();
	}
});
