<?php
/**
 * Plugin Name:       ForgeHub Honeypot Shield
 * Plugin URI:        https://wpforgehub.com/product/honeypot-shield/
 * Description:       Zero-CAPTCHA honeypot and time-trap spam shield for comments, registration, login, and forms with zero external APIs or server bloat.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            WPForgeHub
 * Author URI:        https://wpforgehub.com
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       forgehub-honeypot-shield
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPFH_HPS_VERSION', '1.0.0' );
define( 'WPFH_HPS_FILE', __FILE__ );
define( 'WPFH_HPS_PATH', plugin_dir_path( __FILE__ ) );
define( 'WPFH_HPS_URL', plugin_dir_url( __FILE__ ) );

// <wpfh-pro-only>
/**
 * Freemius SDK helper wrapper (included only in the Pro build).
 *
 * @return object
 */
if ( ! function_exists( 'wpfh_hps_fs' ) ) {
	function wpfh_hps_fs() {
		global $wpfh_hps_fs;

		if ( ! isset( $wpfh_hps_fs ) ) {
			$fs_config = apply_filters(
				'wpfh_hps_fs_config',
				array(
					'id'         => get_option( 'wpfh_hps_fs_id', '' ),
					'public_key' => get_option( 'wpfh_hps_fs_public_key', '' ),
				)
			);
			$force_pro = defined( 'WPFH_HPS_FORCE_PRO' ) && WPFH_HPS_FORCE_PRO;
			$fs_path   = WPFH_HPS_PATH . 'freemius/start.php';

			if ( ! $force_pro && ! empty( $fs_config['id'] ) && ! empty( $fs_config['public_key'] ) && file_exists( $fs_path ) ) {
				require_once $fs_path;
				$wpfh_hps_fs = fs_dynamic_init(
					array(
						'id'             => (string) $fs_config['id'],
						'slug'           => 'forgehub-honeypot-shield',
						'type'           => 'plugin',
						'public_key'     => (string) $fs_config['public_key'],
						'is_premium'     => false,
						'has_addons'     => false,
						'has_paid_plans' => true,
						'menu'           => array(
							'slug'       => 'forgehub-honeypot-shield',
							'first-path' => 'options-general.php?page=forgehub-honeypot-shield',
							'parent'     => array(
								'slug' => 'options-general.php',
							),
						),
					)
				);
				$wpfh_hps_fs->add_action( 'after_uninstall', 'wpfh_hps_uninstall_cleanup' );
			} else {
				$wpfh_hps_fs = new class( $force_pro ) {
					private $force_pro;

					public function __construct( $force_pro = false ) {
						$this->force_pro = (bool) $force_pro;
					}

					public function can_use_premium_code() {
						if ( $this->force_pro ) {
							return true;
						}
						// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
						return (bool) apply_filters( 'fs_can_use_premium_code__forgehub-honeypot-shield', false );
					}

					public function is__premium_only() {
						return $this->can_use_premium_code();
					}

					public function is_plan( $plan ) {
						// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
						return (bool) apply_filters( 'fs_is_plan__forgehub-honeypot-shield', false, $plan );
					}

					public function get_upgrade_url() {
						return 'https://wpforgehub.com/product/honeypot-shield/#pricing';
					}
				};
			}
		}

		return $wpfh_hps_fs;
	}

	wpfh_hps_fs();
}

/**
 * Cleanup plugin data on uninstall (Pro build via after_uninstall hook).
 *
 * @return void
 */
function wpfh_hps_uninstall_cleanup() {
	delete_option( 'wpfh_hps_settings' );
	delete_option( 'wpfh_hps_pro_settings' );
	delete_option( 'wpfh_hps_stats' );
	delete_option( 'wpfh_hps_spam_log' );
	delete_option( 'wpfh_hps_review_nudge' );
}
// </wpfh-pro-only>

/**
 * Return the canonical upgrade URL.
 *
 * @return string
 */
function wpfh_hps_get_upgrade_url() {
	$url = 'https://wpforgehub.com/product/honeypot-shield/#pricing';
	// <wpfh-pro-only>
	if ( function_exists( 'wpfh_hps_fs' ) ) {
		$url = wpfh_hps_fs()->get_upgrade_url();
	}
	// </wpfh-pro-only>
	return $url;
}

/**
 * Check whether Pro features are available and licensed.
 *
 * @return bool
 */
function wpfh_hps_is_pro() {
	$is_pro = false;
	// <wpfh-pro-only>
	$is_pro = file_exists( WPFH_HPS_PATH . 'includes/pro/class-wpfh-hps-pro.php' )
		&& function_exists( 'wpfh_hps_fs' )
		&& wpfh_hps_fs()->can_use_premium_code();
	// </wpfh-pro-only>
	return $is_pro;
}

/**
 * Main Plugin Bootstrap Class.
 */
final class WPFH_Honeypot_Shield {

	/**
	 * Singleton instance.
	 *
	 * @var WPFH_Honeypot_Shield|null
	 */
	private static $instance = null;

	/**
	 * Review nudge instance.
	 *
	 * @var WPFH_Review_Nudge|null
	 */
	private $review_nudge = null;

	/**
	 * Return singleton instance.
	 *
	 * @return WPFH_Honeypot_Shield
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
		add_action( 'plugins_loaded', array( $this, 'init' ), 10 );
		add_filter( 'plugin_action_links_' . plugin_basename( WPFH_HPS_FILE ), array( $this, 'action_links' ) );
		register_activation_hook( WPFH_HPS_FILE, array( $this, 'on_activate' ) );
	}

	/**
	 * Initialize default options on first activation.
	 *
	 * @return void
	 */
	public function on_activate() {
		require_once WPFH_HPS_PATH . 'includes/class-wpfh-hps-settings.php';
		if ( false === get_option( WPFH_HPS_Settings::OPTION_NAME, false ) ) {
			add_option( WPFH_HPS_Settings::OPTION_NAME, WPFH_HPS_Settings::get_defaults() );
		}
	}

	/**
	 * Initialize plugin modules.
	 *
	 * @return void
	 */
	public function init() {
		require_once WPFH_HPS_PATH . 'includes/class-wpfh-review-nudge.php';
		require_once WPFH_HPS_PATH . 'includes/class-wpfh-hps-settings.php';
		require_once WPFH_HPS_PATH . 'includes/class-wpfh-hps-engine.php';
		require_once WPFH_HPS_PATH . 'includes/class-wpfh-hps-admin.php';

		$this->review_nudge = new WPFH_Review_Nudge(
			array(
				'plugin_slug'   => 'forgehub-honeypot-shield',
				'plugin_name'   => 'ForgeHub Honeypot Shield',
				'option_prefix' => 'wpfh_hps',
				'github_url'    => 'https://github.com/WpForgeHub/forgehub-honeypot-shield',
				'min_actions'   => 5,
				'min_days'      => 7,
				'trigger_mode'  => 'or',
				'screens'       => array( 'settings_page_forgehub-honeypot-shield' ),
			)
		);
		$this->review_nudge->register();

		WPFH_HPS_Engine::get_instance();
		WPFH_HPS_Admin::get_instance();

		// <wpfh-pro-only>
		if ( wpfh_hps_is_pro() ) {
			$pro_file = WPFH_HPS_PATH . 'includes/pro/class-wpfh-hps-pro.php';
			if ( file_exists( $pro_file ) ) {
				require_once $pro_file;
				WPFH_HPS_Pro::get_instance();
			}
		}
		// </wpfh-pro-only>
	}

	/**
	 * Return review nudge instance.
	 *
	 * @return WPFH_Review_Nudge|null
	 */
	public function get_review_nudge() {
		return $this->review_nudge;
	}

	/**
	 * Add Settings and calm Priority Support & Pro links to the Plugins screen.
	 *
	 * @param array $links Existing action links.
	 * @return array
	 */
	public function action_links( $links ) {
		$settings_url = admin_url( 'options-general.php?page=forgehub-honeypot-shield' );
		$custom_links = array(
			'<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Settings', 'forgehub-honeypot-shield' ) . '</a>',
		);

		if ( ! wpfh_hps_is_pro() ) {
			$custom_links[] = '<a href="' . esc_url( wpfh_hps_get_upgrade_url() ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Priority Support & Pro', 'forgehub-honeypot-shield' ) . '</a>';
		}

		return array_merge( $custom_links, $links );
	}
}

WPFH_Honeypot_Shield::get_instance();
