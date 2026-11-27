/* ForgeHub Honeypot Shield — Admin Interactions */
(function () {
	'use strict';

	document.addEventListener('DOMContentLoaded', function () {
		if (typeof window.wpfhHpsAdmin === 'undefined') {
			return;
		}

		var cfg = window.wpfhHpsAdmin;
		var resetBtn = document.getElementById('wpfh-hps-reset-stats');
		var feedback = document.getElementById('wpfh-hps-stats-feedback');

		if (resetBtn) {
			resetBtn.addEventListener('click', function () {
				resetBtn.disabled = true;
				var body = new window.URLSearchParams();
				body.append('action', 'wpfh_hps_reset_stats');
				body.append('nonce', cfg.nonce);

				window.fetch(cfg.ajaxUrl, {
					method: 'POST',
					credentials: 'same-origin',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
					body: body.toString()
				})
					.then(function (r) { return r.json(); })
					.then(function (res) {
						if (res && res.success) {
							['total', 'comments', 'registration', 'login'].forEach(function (k) {
								var el = document.getElementById('wpfh-hps-stat-' + k);
								if (el) {
									el.textContent = '0';
								}
							});
							if (feedback) {
								feedback.textContent = cfg.i18n.resetDone;
							}
						} else if (feedback) {
							feedback.textContent = cfg.i18n.requestFailed;
						}
					})
					.catch(function () {
						if (feedback) {
							feedback.textContent = cfg.i18n.requestFailed;
						}
					})
					.finally(function () {
						resetBtn.disabled = false;
					});
			});
		}

		var clearLogBtn = document.getElementById('wpfh-hps-clear-log');
		var logContainer = document.getElementById('wpfh-hps-log-container');
		if (clearLogBtn && logContainer) {
			clearLogBtn.addEventListener('click', function () {
				clearLogBtn.disabled = true;
				var body = new window.URLSearchParams();
				body.append('action', 'wpfh_hps_clear_log');
				body.append('nonce', cfg.nonce);

				window.fetch(cfg.ajaxUrl, {
					method: 'POST',
					credentials: 'same-origin',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
					body: body.toString()
				})
					.then(function (r) { return r.json(); })
					.then(function (res) {
						if (res && res.success) {
							logContainer.innerHTML = '<p class="wpfh-hps-empty">' + cfg.i18n.clearLogDone + '</p>';
						}
					})
					.finally(function () {
						clearLogBtn.disabled = false;
					});
			});
		}
	});
})();
