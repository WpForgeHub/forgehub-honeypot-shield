<?php
/**
 * Admin Settings Page & AJAX Actions for ForgeHub Honeypot Shield.
 *
 * @package ForgeHub_Honeypot_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_HPS_Admin
 */
class WPFH_HPS_Admin {

	/**
	 * Singleton instance.
	 *
	 * @var WPFH_HPS_Admin|null
	 */
	private static $instance = null;

	/**
	 * Return singleton instance.
	 *
	 * @return WPFH_HPS_Admin
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
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_wpfh_hps_reset_stats', array( $this, 'ajax_reset_stats' ) );
	}

	/**
	 * Register Settings submenu page.
	 *
	 * @return void
	 */
	public function register_menu() {
		add_options_page(
			__( 'ForgeHub Honeypot Shield', 'forgehub-honeypot-shield' ),
			__( 'Honeypot Shield', 'forgehub-honeypot-shield' ),
			'manage_options',
			'forgehub-honeypot-shield',
			array( $this, 'render_page' )
		);
	}

	/**
	 * Register plugin settings.
	 *
	 * @return void
	 */
	public function register_settings() {
		register_setting(
			'wpfh_hps_settings_group',
			WPFH_HPS_Settings::OPTION_NAME,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'WPFH_HPS_Settings', 'sanitize' ),
				'default'           => WPFH_HPS_Settings::get_defaults(),
			)
		);

		// <wpfh-pro-only>
		if ( wpfh_hps_is_pro() ) {
			register_setting(
				'wpfh_hps_settings_group',
				WPFH_HPS_Settings::PRO_OPTION_NAME,
				array(
					'type'              => 'array',
					'sanitize_callback' => array( 'WPFH_HPS_Settings', 'sanitize_pro' ),
					'default'           => WPFH_HPS_Settings::get_pro_defaults(),
				)
			);
		}
		// </wpfh-pro-only>
	}

	/**
	 * Enqueue admin CSS and JS with filemtime cache-busting.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_assets( $hook ) {
		if ( 'settings_page_forgehub-honeypot-shield' !== $hook ) {
			return;
		}

		$css_path = WPFH_HPS_PATH . 'assets/admin.css';
		$js_path  = WPFH_HPS_PATH . 'assets/admin.js';

		wp_enqueue_style(
			'wpfh-hps-admin',
			WPFH_HPS_URL . 'assets/admin.css',
			array(),
			file_exists( $css_path ) ? (string) filemtime( $css_path ) : WPFH_HPS_VERSION
		);

		wp_enqueue_script(
			'wpfh-hps-admin',
			WPFH_HPS_URL . 'assets/admin.js',
			array(),
			file_exists( $js_path ) ? (string) filemtime( $js_path ) : WPFH_HPS_VERSION,
			true
		);

		wp_localize_script(
			'wpfh-hps-admin',
			'wpfhHpsAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'wpfh_hps_admin_nonce' ),
				'isPro'   => wpfh_hps_is_pro(),
				'i18n'    => array(
					'resetDone'     => __( 'Blocked spam counters reset to zero.', 'forgehub-honeypot-shield' ),
					'clearLogDone'  => __( 'Spam log cleared.', 'forgehub-honeypot-shield' ),
					'requestFailed' => __( 'Request failed. Please try again.', 'forgehub-honeypot-shield' ),
				),
			)
		);
	}

	/**
	 * AJAX handler: reset blocked spam statistics.
	 *
	 * @return void
	 */
	public function ajax_reset_stats() {
		check_ajax_referer( 'wpfh_hps_admin_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'forgehub-honeypot-shield' ) ), 403 );
		}

		WPFH_HPS_Settings::reset_stats();
		wp_send_json_success( WPFH_HPS_Settings::get_stats() );
	}

	/**
	 * Render the Settings page (Zero-Nag, WCAG 2.1 AA compliant).
	 *
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$settings = WPFH_HPS_Settings::get();
		$stats    = WPFH_HPS_Settings::get_stats();
		$is_pro   = wpfh_hps_is_pro();
		?>
		<div class="wrap wpfh-hps-wrap">
			<div class="wpfh-hps-header">
				<div>
					<h1><?php esc_html_e( 'ForgeHub Honeypot Shield', 'forgehub-honeypot-shield' ); ?></h1>
					<p class="wpfh-hps-subtitle">
						<?php esc_html_e( 'Zero-CAPTCHA invisible honeypot and signed time-trap spam protection for comments, registration, login, and forms.', 'forgehub-honeypot-shield' ); ?>
					</p>
				</div>
				<div class="wpfh-hps-header-badges">
					<span class="wpfh-hps-pill">
						<?php
						/* translators: %s: plugin version number. */
						echo esc_html( sprintf( __( 'v%s', 'forgehub-honeypot-shield' ), WPFH_HPS_VERSION ) );
						?>
					</span>
					<?php if ( $is_pro ) : ?>
						<span class="wpfh-hps-pill wpfh-hps-pill--pro"><?php esc_html_e( 'PRO ACTIVE', 'forgehub-honeypot-shield' ); ?></span>
					<?php endif; ?>
				</div>
			</div>

			<?php settings_errors(); ?>

			<div class="wpfh-hps-card">
				<div class="wpfh-hps-card-head">
					<div>
						<h2><?php esc_html_e( 'Protection Overview', 'forgehub-honeypot-shield' ); ?></h2>
						<span class="wpfh-hps-badge <?php echo ! empty( $settings['enabled'] ) ? 'wpfh-hps-badge--ok' : 'wpfh-hps-badge--warn'; ?>">
							<?php echo ! empty( $settings['enabled'] ) ? esc_html__( 'Shield Active', 'forgehub-honeypot-shield' ) : esc_html__( 'Shield Paused', 'forgehub-honeypot-shield' ); ?>
						</span>
					</div>
					<button type="button" id="wpfh-hps-reset-stats" class="button button-secondary">
						<?php esc_html_e( 'Reset Counters', 'forgehub-honeypot-shield' ); ?>
					</button>
				</div>

				<div class="wpfh-hps-metrics">
					<div class="wpfh-hps-metric">
						<span class="wpfh-hps-metric-label"><?php esc_html_e( 'Total Spam Blocked', 'forgehub-honeypot-shield' ); ?></span>
						<strong id="wpfh-hps-stat-total"><?php echo esc_html( (string) (int) $stats['total'] ); ?></strong>
					</div>
					<div class="wpfh-hps-metric">
						<span class="wpfh-hps-metric-label"><?php esc_html_e( 'Comments', 'forgehub-honeypot-shield' ); ?></span>
						<strong id="wpfh-hps-stat-comments"><?php echo esc_html( (string) (int) $stats['comments'] ); ?></strong>
					</div>
					<div class="wpfh-hps-metric">
						<span class="wpfh-hps-metric-label"><?php esc_html_e( 'Registration', 'forgehub-honeypot-shield' ); ?></span>
						<strong id="wpfh-hps-stat-registration"><?php echo esc_html( (string) (int) $stats['registration'] ); ?></strong>
					</div>
					<div class="wpfh-hps-metric">
						<span class="wpfh-hps-metric-label"><?php esc_html_e( 'Login & Recovery', 'forgehub-honeypot-shield' ); ?></span>
						<strong id="wpfh-hps-stat-login"><?php echo esc_html( (string) ( (int) $stats['login'] + (int) $stats['lostpassword'] ) ); ?></strong>
					</div>
				</div>
				<div id="wpfh-hps-stats-feedback" class="wpfh-hps-inline-feedback" aria-live="polite"></div>
			</div>

			<form method="post" action="options.php">
				<?php settings_fields( 'wpfh_hps_settings_group' ); ?>

				<div class="wpfh-hps-card">
					<div class="wpfh-hps-card-head">
						<h2><?php esc_html_e( 'Core Honeypot & Time-Trap Settings', 'forgehub-honeypot-shield' ); ?></h2>
					</div>

					<table class="form-table wpfh-hps-table" role="presentation">
						<tr>
							<th scope="row"><?php esc_html_e( 'Enable Honeypot Shield', 'forgehub-honeypot-shield' ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[enabled]" value="1" <?php checked( ! empty( $settings['enabled'] ) ); ?> />
									<?php esc_html_e( 'Protect forms with an invisible honeypot field and HMAC-signed time trap (no CAPTCHA puzzles).', 'forgehub-honeypot-shield' ); ?>
								</label>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Protected WordPress Surfaces', 'forgehub-honeypot-shield' ); ?></th>
							<td>
								<fieldset class="wpfh-hps-checklist">
									<label>
										<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[protect_comments]" value="1" <?php checked( ! empty( $settings['protect_comments'] ) ); ?> />
										<?php esc_html_e( 'Post & Page Comments', 'forgehub-honeypot-shield' ); ?>
									</label>
									<label>
										<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[protect_registration]" value="1" <?php checked( ! empty( $settings['protect_registration'] ) ); ?> />
										<?php esc_html_e( 'User Registration Form', 'forgehub-honeypot-shield' ); ?>
									</label>
									<label>
										<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[protect_login]" value="1" <?php checked( ! empty( $settings['protect_login'] ) ); ?> />
										<?php esc_html_e( 'Login Form (wp-login.php)', 'forgehub-honeypot-shield' ); ?>
									</label>
									<label>
										<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[protect_lostpassword]" value="1" <?php checked( ! empty( $settings['protect_lostpassword'] ) ); ?> />
										<?php esc_html_e( 'Lost Password Form', 'forgehub-honeypot-shield' ); ?>
									</label>
								</fieldset>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="wpfh_hps_field_name"><?php esc_html_e( 'Honeypot Field Name', 'forgehub-honeypot-shield' ); ?></label>
							</th>
							<td>
								<input type="text" id="wpfh_hps_field_name" class="regular-text code" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[honeypot_field_name]" value="<?php echo esc_attr( $settings['honeypot_field_name'] ); ?>" />
								<p class="description">
									<?php esc_html_e( 'Hidden trap input name (lowercase letters, numbers, underscores). Humans never see it; bots auto-fill it.', 'forgehub-honeypot-shield' ); ?>
								</p>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="wpfh_hps_min_seconds"><?php esc_html_e( 'Minimum Submit Time (seconds)', 'forgehub-honeypot-shield' ); ?></label>
							</th>
							<td>
								<input type="number" id="wpfh_hps_min_seconds" class="small-text" min="0" max="30" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[min_submit_seconds]" value="<?php echo esc_attr( (string) (int) $settings['min_submit_seconds'] ); ?>" />
								<p class="description">
									<?php esc_html_e( 'Reject submissions sent faster than this many seconds after the form loaded (recommended: 2–4 seconds; 0 disables time trap).', 'forgehub-honeypot-shield' ); ?>
								</p>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="wpfh_hps_comment_action"><?php esc_html_e( 'Action on Comment Spam', 'forgehub-honeypot-shield' ); ?></label>
							</th>
							<td>
								<select id="wpfh_hps_comment_action" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[comment_action]">
									<option value="reject" <?php selected( $settings['comment_action'], 'reject' ); ?>>
										<?php esc_html_e( 'Reject Immediately (HTTP 403 — zero database clutter)', 'forgehub-honeypot-shield' ); ?>
									</option>
									<option value="spam" <?php selected( $settings['comment_action'], 'spam' ); ?>>
										<?php esc_html_e( 'Mark as Spam (send to Comments > Spam queue)', 'forgehub-honeypot-shield' ); ?>
									</option>
								</select>
							</td>
						</tr>
						<tr>
							<th scope="row">
								<label for="wpfh_hps_block_message"><?php esc_html_e( 'Rejection Message', 'forgehub-honeypot-shield' ); ?></label>
							</th>
							<td>
								<input type="text" id="wpfh_hps_block_message" class="large-text" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[block_message]" value="<?php echo esc_attr( $settings['block_message'] ); ?>" />
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'Administrator Bypass', 'forgehub-honeypot-shield' ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( WPFH_HPS_Settings::OPTION_NAME ); ?>[bypass_logged_in_admins]" value="1" <?php checked( ! empty( $settings['bypass_logged_in_admins'] ) ); ?> />
									<?php esc_html_e( 'Bypass honeypot checks for logged-in administrators.', 'forgehub-honeypot-shield' ); ?>
								</label>
							</td>
						</tr>
					</table>
				</div>

				<?php
				/**
				 * Hook for Pro settings panels (rendered only when Pro module is active).
				 */
				do_action( 'wpfh_hps_render_pro_settings' );
				?>

				<p class="submit">
					<?php submit_button( __( 'Save Shield Settings', 'forgehub-honeypot-shield' ), 'primary', 'submit', false ); ?>
				</p>
			</form>

			<?php
			/**
			 * Hook for Pro spam log panel (rendered only when Pro module is active).
			 */
			do_action( 'wpfh_hps_render_pro_panels' );
			?>

			<?php if ( ! $is_pro ) : ?>
				<div class="wpfh-hps-calm-footer">
					<span>
						<?php esc_html_e( 'Need WooCommerce, Contact Form 7, WPForms integration, spam logs, or priority email support?', 'forgehub-honeypot-shield' ); ?>
					</span>
					<a href="<?php echo esc_url( wpfh_hps_get_upgrade_url() ); ?>" target="_blank" rel="noopener noreferrer">
						<?php esc_html_e( 'Priority Support & Pro', 'forgehub-honeypot-shield' ); ?> &rarr;
					</a>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}
}
