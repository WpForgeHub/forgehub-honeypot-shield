<?php
/**
 * Pro Module for ForgeHub Honeypot Shield.
 *
 * Provides WooCommerce Checkout/Registration, Contact Form 7, WPForms integration,
 * advanced content/email/IP rules, and local spam activity logging with CSV export.
 *
 * @package ForgeHub_Honeypot_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_HPS_Pro
 */
class WPFH_HPS_Pro {

	const LOG_OPTION  = 'wpfh_hps_spam_log';
	const MAX_ENTRIES = 100;

	/**
	 * Singleton instance.
	 *
	 * @var WPFH_HPS_Pro|null
	 */
	private static $instance = null;

	/**
	 * Return singleton instance.
	 *
	 * @return WPFH_HPS_Pro
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$settings = WPFH_HPS_Settings::get();
		$pro      = WPFH_HPS_Settings::get_pro();

		// Admin UI hooks.
		add_action( 'wpfh_hps_render_pro_settings', array( $this, 'render_pro_settings' ) );
		add_action( 'wpfh_hps_render_pro_panels', array( $this, 'render_spam_log_panel' ) );
		add_action( 'wp_ajax_wpfh_hps_clear_log', array( $this, 'ajax_clear_log' ) );
		add_action( 'admin_post_wpfh_hps_export_log', array( $this, 'handle_export_csv' ) );

		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		// IP allowlist bypass & advanced validation rules.
		add_filter( 'wpfh_hps_should_bypass', array( $this, 'filter_ip_allowlist_bypass' ) );
		add_filter( 'wpfh_hps_extra_validation', array( $this, 'filter_extra_rules' ), 10, 3 );

		// Spam event logger.
		if ( ! empty( $pro['enable_spam_log'] ) ) {
			add_action( 'wpfh_hps_spam_blocked', array( $this, 'log_blocked_event' ), 10, 3 );
		}

		// WooCommerce Checkout & Registration protection.
		if ( ! empty( $pro['protect_woocommerce'] ) ) {
			add_action( 'woocommerce_after_order_notes', array( $this, 'render_wc_honeypot' ) );
			add_action( 'woocommerce_checkout_process', array( $this, 'validate_wc_checkout' ) );
			add_action( 'woocommerce_register_form', array( $this, 'render_wc_honeypot' ) );
			add_filter( 'woocommerce_process_registration_errors', array( $this, 'validate_wc_registration' ), 10, 4 );
		}

		// Contact Form 7 protection.
		if ( ! empty( $pro['protect_cf7'] ) ) {
			add_filter( 'wpcf7_form_elements', array( $this, 'inject_cf7_honeypot' ) );
			add_filter( 'wpcf7_spam', array( $this, 'validate_cf7_submission' ), 10, 2 );
		}

		// WPForms protection.
		if ( ! empty( $pro['protect_wpforms'] ) ) {
			add_action( 'wpforms_display_submit_before', array( $this, 'render_wc_honeypot' ) );
			add_filter( 'wpforms_process_initial_errors', array( $this, 'validate_wpforms_submission' ), 10, 2 );
		}
	}

	/**
	 * Return current visitor IP address.
	 *
	 * @return string
	 */
	public static function get_client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( '' !== $ip && false !== filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $ip;
		}
		return '0.0.0.0';
	}

	/**
	 * Mask IP address for privacy-friendly local logging.
	 *
	 * @param string $ip Raw IP.
	 * @return string
	 */
	public static function mask_ip( $ip ) {
		if ( false !== strpos( $ip, ':' ) ) {
			$parts = explode( ':', $ip );
			return implode( ':', array_slice( $parts, 0, 3 ) ) . ':****';
		}
		$parts = explode( '.', $ip );
		if ( 4 === count( $parts ) ) {
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.xxx';
		}
		return 'unknown';
	}

	/**
	 * Check IP allowlist for bypass.
	 *
	 * @param bool $bypass Current bypass flag.
	 * @return bool
	 */
	public function filter_ip_allowlist_bypass( $bypass ) {
		if ( $bypass ) {
			return true;
		}
		$pro = WPFH_HPS_Settings::get_pro();
		if ( empty( $pro['ip_allowlist'] ) ) {
			return false;
		}
		$allowed = array_filter( array_map( 'trim', explode( "\n", $pro['ip_allowlist'] ) ) );
		return in_array( self::get_client_ip(), $allowed, true );
	}

	/**
	 * Evaluate Pro extra spam rules (keywords, max links, disposable emails).
	 *
	 * @param array  $result  Current validation result.
	 * @param string $surface Surface name.
	 * @param array  $context Submission context.
	 * @return array
	 */
	public function filter_extra_rules( $result, $surface, $context ) {
		if ( ! empty( $result['blocked'] ) ) {
			return $result;
		}

		$pro     = WPFH_HPS_Settings::get_pro();
		$content = isset( $context['content'] ) ? (string) $context['content'] : '';
		$email   = isset( $context['email'] ) ? strtolower( trim( (string) $context['email'] ) ) : '';

		// 1. Max links in comments.
		$max_links = (int) $pro['max_comment_links'];
		if ( 'comments' === $surface && $max_links > 0 && '' !== $content ) {
			$link_count = preg_match_all( '#https?://#i', $content, $matches );
			if ( $link_count > $max_links ) {
				return array(
					'blocked' => true,
					'reason'  => 'max_links_exceeded',
				);
			}
		}

		// 2. Keyword blacklist.
		if ( '' !== $pro['blocked_keywords'] && '' !== $content ) {
			$keywords = array_filter( array_map( 'trim', explode( "\n", $pro['blocked_keywords'] ) ) );
			foreach ( $keywords as $kw ) {
				if ( '' !== $kw && false !== stripos( $content, $kw ) ) {
					return array(
						'blocked' => true,
						'reason'  => 'blocked_keyword',
					);
				}
			}
		}

		// 3. Disposable email domains.
		if ( ! empty( $pro['block_disposable_emails'] ) && '' !== $email && false !== strpos( $email, '@' ) ) {
			$domain  = substr( strrchr( $email, '@' ), 1 );
			$domains = array_filter( array_map( 'trim', explode( "\n", strtolower( $pro['disposable_domains'] ) ) ) );
			if ( in_array( $domain, $domains, true ) ) {
				return array(
					'blocked' => true,
					'reason'  => 'disposable_email',
				);
			}
		}

		return $result;
	}

	/**
	 * Render honeypot HTML inside WooCommerce / WPForms forms.
	 *
	 * @return void
	 */
	public function render_wc_honeypot() {
		WPFH_HPS_Engine::get_instance()->render_honeypot_fields();
	}

	/**
	 * Validate WooCommerce checkout submission.
	 *
	 * @return void
	 */
	public function validate_wc_checkout() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WooCommerce checkout verifies its own nonce before this hook.
		$payload = wp_unslash( $_POST );
		$email   = isset( $payload['billing_email'] ) ? sanitize_email( (string) $payload['billing_email'] ) : '';
		$check   = WPFH_HPS_Engine::get_instance()->check_submission( $payload, 'woocommerce_checkout', array( 'email' => $email ) );

		if ( ! empty( $check['blocked'] ) && function_exists( 'wc_add_notice' ) ) {
			$settings = WPFH_HPS_Settings::get();
			wc_add_notice( $settings['block_message'], 'error' );
		}
	}

	/**
	 * Validate WooCommerce registration submission.
	 *
	 * @param WP_Error $errors   Errors object.
	 * @param string   $username Username.
	 * @param string   $password Password.
	 * @param string   $email    Email.
	 * @return WP_Error
	 */
	public function validate_wc_registration( $errors, $username, $password, $email ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WooCommerce registration verifies its own nonce.
		$payload = wp_unslash( $_POST );
		$check   = WPFH_HPS_Engine::get_instance()->check_submission( $payload, 'woocommerce_register', array( 'email' => (string) $email ) );

		if ( ! empty( $check['blocked'] ) ) {
			$settings = WPFH_HPS_Settings::get();
			$errors->add( 'wpfh_hps_spam', $settings['block_message'] );
		}

		return $errors;
	}

	/**
	 * Append honeypot markup to Contact Form 7 forms.
	 *
	 * @param string $html Form elements HTML.
	 * @return string
	 */
	public function inject_cf7_honeypot( $html ) {
		$engine = WPFH_HPS_Engine::get_instance();
		if ( $engine->should_bypass() ) {
			return $html;
		}
		return $html . $engine->get_honeypot_html();
	}

	/**
	 * Validate Contact Form 7 submission.
	 *
	 * @param bool  $spam       Current spam flag.
	 * @param mixed $submission CF7 submission object.
	 * @return bool
	 */
	public function validate_cf7_submission( $spam, $submission = null ) {
		if ( $spam ) {
			return true;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- CF7 handles its own REST/form nonce.
		$payload = wp_unslash( $_POST );
		$check   = WPFH_HPS_Engine::get_instance()->check_submission( $payload, 'contact_form_7' );
		return ! empty( $check['blocked'] );
	}

	/**
	 * Validate WPForms submission.
	 *
	 * @param array $errors    Current form errors.
	 * @param array $form_data Form data.
	 * @return array
	 */
	public function validate_wpforms_submission( $errors, $form_data ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WPForms verifies its own nonce.
		$payload = wp_unslash( $_POST );
		$check   = WPFH_HPS_Engine::get_instance()->check_submission( $payload, 'wpforms' );
		if ( ! empty( $check['blocked'] ) ) {
			$form_id                     = isset( $form_data['id'] ) ? absint( $form_data['id'] ) : 0;
			$settings                    = WPFH_HPS_Settings::get();
			$errors[ $form_id ]['header'] = $settings['block_message'];
		}
		return $errors;
	}

	/**
	 * Record a blocked spam attempt in the local ring-buffer log.
	 *
	 * @param string $surface Surface identifier.
	 * @param string $reason  Reason code.
	 * @param array  $context Optional context.
	 * @return void
	 */
	public function log_blocked_event( $surface, $reason, $context = array() ) {
		$log = get_option( self::LOG_OPTION, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$pro            = WPFH_HPS_Settings::get_pro();
		$retention_days = max( 1, (int) $pro['log_retention_days'] );
		$cutoff         = time() - ( $retention_days * DAY_IN_SECONDS );

		$log = array_values(
			array_filter(
				$log,
				static function ( $row ) use ( $cutoff ) {
					return isset( $row['ts'] ) && (int) $row['ts'] >= $cutoff;
				}
			)
		);

		$ua = isset( $_SERVER['HTTP_USER_AGENT'] )
			? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 120 )
			: '';

		array_unshift(
			$log,
			array(
				'ts'      => time(),
				'time'    => gmdate( 'Y-m-d H:i:s' ),
				'surface' => sanitize_key( $surface ),
				'reason'  => sanitize_key( $reason ),
				'ip'      => self::mask_ip( self::get_client_ip() ),
				'ua'      => $ua,
			)
		);

		if ( count( $log ) > self::MAX_ENTRIES ) {
			$log = array_slice( $log, 0, self::MAX_ENTRIES );
		}

		update_option( self::LOG_OPTION, $log, false );
	}

	/**
	 * Return stored spam log entries.
	 *
	 * @return array
	 */
	public static function get_log() {
		$log = get_option( self::LOG_OPTION, array() );
		return is_array( $log ) ? $log : array();
	}

	/**
	 * AJAX handler: clear spam log.
	 *
	 * @return void
	 */
	public function ajax_clear_log() {
		check_ajax_referer( 'wpfh_hps_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'forgehub-honeypot-shield' ) ), 403 );
		}

		delete_option( self::LOG_OPTION );
		wp_send_json_success( array( 'cleared' => true ) );
	}

	/**
	 * Export spam log as CSV download.
	 *
	 * @return void
	 */
	public function handle_export_csv() {
		check_admin_referer( 'wpfh_hps_export_log_action' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to export logs.', 'forgehub-honeypot-shield' ) );
		}

		$log = self::get_log();
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="forgehub-honeypot-shield-log.csv"' );

		$lines = array(
			self::format_csv_row( array( 'Timestamp (UTC)', 'Surface', 'Reason', 'Masked IP', 'User Agent' ) ),
		);
		foreach ( $log as $row ) {
			$lines[] = self::format_csv_row(
				array(
					isset( $row['time'] ) ? $row['time'] : '',
					isset( $row['surface'] ) ? $row['surface'] : '',
					isset( $row['reason'] ) ? $row['reason'] : '',
					isset( $row['ip'] ) ? $row['ip'] : '',
					isset( $row['ua'] ) ? $row['ua'] : '',
				)
			);
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Streaming raw RFC 4180 CSV download with text/csv Content-Type header.
		echo implode( '', $lines );
		exit;
	}

	/**
	 * Format an array of values as a single RFC 4180 CSV row with formula-injection guard.
	 *
	 * @param array $fields Column values.
	 * @return string
	 */
	private static function format_csv_row( array $fields ) {
		$escaped = array();
		foreach ( $fields as $field ) {
			$val = str_replace( array( "\r\n", "\r", "\n" ), ' ', (string) $field );
			if ( '' !== $val && in_array( $val[0], array( '=', '+', '-', '@' ), true ) ) {
				$val = "'" . $val;
			}
			$escaped[] = '"' . str_replace( '"', '""', $val ) . '"';
		}
		return implode( ',', $escaped ) . "\r\n";
	}

	/**
	 * Render Pro settings card inside the main Settings form.
	 *
	 * @return void
	 */
	public function render_pro_settings() {
		$pro = WPFH_HPS_Settings::get_pro();
		?>
		<div class="wpfh-hps-card">
			<div class="wpfh-hps-card-head">
				<h2><?php esc_html_e( 'Pro Integrations & Advanced Rules', 'forgehub-honeypot-shield' ); ?></h2>
				<span class="wpfh-hps-pill wpfh-hps-pill--pro"><?php esc_html_e( 'PRO', 'forgehub-honeypot-shield' ); ?></span>
			</div>

			<table class="form-table wpfh-hps-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Third-Party Form Integrations', 'forgehub-honeypot-shield' ); ?></th>
					<td>
						<fieldset class="wpfh-hps-checklist">
							<label>
								<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[protect_woocommerce]" value="1" <?php checked( ! empty( $pro['protect_woocommerce'] ) ); ?> />
								<?php esc_html_e( 'WooCommerce Checkout & Customer Registration', 'forgehub-honeypot-shield' ); ?>
							</label>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[protect_cf7]" value="1" <?php checked( ! empty( $pro['protect_cf7'] ) ); ?> />
								<?php esc_html_e( 'Contact Form 7 Forms', 'forgehub-honeypot-shield' ); ?>
							</label>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[protect_wpforms]" value="1" <?php checked( ! empty( $pro['protect_wpforms'] ) ); ?> />
								<?php esc_html_e( 'WPForms Submissions', 'forgehub-honeypot-shield' ); ?>
							</label>
						</fieldset>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="wpfh_hps_max_links"><?php esc_html_e( 'Max URLs Allowed in Comments', 'forgehub-honeypot-shield' ); ?></label>
					</th>
					<td>
						<input type="number" id="wpfh_hps_max_links" class="small-text" min="0" max="50" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[max_comment_links]" value="<?php echo esc_attr( (string) (int) $pro['max_comment_links'] ); ?>" />
						<p class="description"><?php esc_html_e( '0 disables link-count filtering. Example: set 2 to block link-stuffing spam comments.', 'forgehub-honeypot-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="wpfh_hps_keywords"><?php esc_html_e( 'Blocked Spam Keywords', 'forgehub-honeypot-shield' ); ?></label>
					</th>
					<td>
						<textarea id="wpfh_hps_keywords" rows="3" class="large-text code" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[blocked_keywords]"><?php echo esc_textarea( $pro['blocked_keywords'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One phrase per line (case-insensitive). Matching comments are rejected.', 'forgehub-honeypot-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Disposable Email Protection', 'forgehub-honeypot-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[block_disposable_emails]" value="1" <?php checked( ! empty( $pro['block_disposable_emails'] ) ); ?> />
							<?php esc_html_e( 'Block throwaway / disposable email domains on registration and comments.', 'forgehub-honeypot-shield' ); ?>
						</label>
						<textarea rows="3" class="large-text code" style="margin-top:8px;" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[disposable_domains]"><?php echo esc_textarea( $pro['disposable_domains'] ); ?></textarea>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="wpfh_hps_ip_allowlist"><?php esc_html_e( 'Trusted IP Allowlist', 'forgehub-honeypot-shield' ); ?></label>
					</th>
					<td>
						<textarea id="wpfh_hps_ip_allowlist" rows="2" class="large-text code" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[ip_allowlist]"><?php echo esc_textarea( $pro['ip_allowlist'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One IPv4/IPv6 address per line to bypass honeypot checks (e.g. automated QA or office IP).', 'forgehub-honeypot-shield' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Spam Activity Log', 'forgehub-honeypot-shield' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[enable_spam_log]" value="1" <?php checked( ! empty( $pro['enable_spam_log'] ) ); ?> />
							<?php esc_html_e( 'Record blocked attempts locally (up to 100 latest entries, masked IP for privacy).', 'forgehub-honeypot-shield' ); ?>
						</label>
						<div style="margin-top:8px;">
							<label for="wpfh_hps_retention"><?php esc_html_e( 'Retention (days):', 'forgehub-honeypot-shield' ); ?></label>
							<input type="number" id="wpfh_hps_retention" class="small-text" min="1" max="365" name="<?php echo esc_attr( WPFH_HPS_Settings::PRO_OPTION_NAME ); ?>[log_retention_days]" value="<?php echo esc_attr( (string) (int) $pro['log_retention_days'] ); ?>" />
						</div>
					</td>
				</tr>
			</table>
		</div>
		<?php
	}

	/**
	 * Render Pro Spam Activity Log table below the main settings form.
	 *
	 * @return void
	 */
	public function render_spam_log_panel() {
		$log        = self::get_log();
		$export_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=wpfh_hps_export_log' ),
			'wpfh_hps_export_log_action'
		);
		?>
		<div class="wpfh-hps-card">
			<div class="wpfh-hps-card-head">
				<h2><?php esc_html_e( 'Recent Blocked Spam Log', 'forgehub-honeypot-shield' ); ?></h2>
				<div class="wpfh-hps-log-actions">
					<a href="<?php echo esc_url( $export_url ); ?>" class="button button-secondary">
						<?php esc_html_e( 'Export CSV', 'forgehub-honeypot-shield' ); ?>
					</a>
					<button type="button" id="wpfh-hps-clear-log" class="button button-secondary">
						<?php esc_html_e( 'Clear Log', 'forgehub-honeypot-shield' ); ?>
					</button>
				</div>
			</div>
			<div id="wpfh-hps-log-container">
				<?php if ( empty( $log ) ) : ?>
					<p class="wpfh-hps-empty"><?php esc_html_e( 'No blocked spam events recorded yet.', 'forgehub-honeypot-shield' ); ?></p>
				<?php else : ?>
					<table class="widefat striped wpfh-hps-log-table">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Time (UTC)', 'forgehub-honeypot-shield' ); ?></th>
								<th><?php esc_html_e( 'Surface', 'forgehub-honeypot-shield' ); ?></th>
								<th><?php esc_html_e( 'Reason', 'forgehub-honeypot-shield' ); ?></th>
								<th><?php esc_html_e( 'Masked IP', 'forgehub-honeypot-shield' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( array_slice( $log, 0, 25 ) as $entry ) : ?>
								<tr>
									<td><?php echo esc_html( isset( $entry['time'] ) ? $entry['time'] : '' ); ?></td>
									<td><code><?php echo esc_html( isset( $entry['surface'] ) ? $entry['surface'] : '' ); ?></code></td>
									<td><?php echo esc_html( isset( $entry['reason'] ) ? $entry['reason'] : '' ); ?></td>
									<td><code><?php echo esc_html( isset( $entry['ip'] ) ? $entry['ip'] : '' ); ?></code></td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}
}
