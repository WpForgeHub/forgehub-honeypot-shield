<?php
/**
 * Core Zero-CAPTCHA Honeypot & Time-Trap Protection Engine.
 *
 * @package ForgeHub_Honeypot_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_HPS_Engine
 */
class WPFH_HPS_Engine {

	/**
	 * Singleton instance.
	 *
	 * @var WPFH_HPS_Engine|null
	 */
	private static $instance = null;

	/**
	 * Whether comment should be marked as spam instead of rejected.
	 *
	 * @var bool
	 */
	private $flag_comment_as_spam = false;

	/**
	 * Return singleton instance.
	 *
	 * @return WPFH_HPS_Engine
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
		if ( empty( $settings['enabled'] ) ) {
			return;
		}

		if ( ! empty( $settings['protect_comments'] ) ) {
			add_action( 'comment_form_after_fields', array( $this, 'render_honeypot_fields' ) );
			add_action( 'comment_form_logged_in_after', array( $this, 'render_honeypot_fields' ) );
			add_filter( 'preprocess_comment', array( $this, 'validate_comment' ), 5 );
			add_filter( 'pre_comment_approved', array( $this, 'filter_comment_approved' ), 99, 2 );
		}

		if ( ! empty( $settings['protect_registration'] ) ) {
			add_action( 'register_form', array( $this, 'render_honeypot_fields' ) );
			add_filter( 'registration_errors', array( $this, 'validate_registration' ), 10, 3 );
		}

		if ( ! empty( $settings['protect_login'] ) ) {
			add_action( 'login_form', array( $this, 'render_honeypot_fields' ) );
			add_filter( 'authenticate', array( $this, 'validate_login' ), 25, 3 );
		}

		if ( ! empty( $settings['protect_lostpassword'] ) ) {
			add_action( 'lostpassword_form', array( $this, 'render_honeypot_fields' ) );
			add_action( 'lostpassword_post', array( $this, 'validate_lostpassword' ), 10, 2 );
		}
	}

	/**
	 * Build an HMAC-signed timestamp token for time-trap validation.
	 *
	 * @param int|null $timestamp Optional Unix timestamp (defaults to current time).
	 * @return string
	 */
	public static function generate_time_token( $timestamp = null ) {
		$ts  = null === $timestamp ? time() : (int) $timestamp;
		$sig = hash_hmac( 'sha256', (string) $ts, wp_salt( 'nonce' ) );
		return $ts . '.' . substr( $sig, 0, 16 );
	}

	/**
	 * Verify an HMAC-signed timestamp token and return the timestamp or false.
	 *
	 * @param string $token Raw token string.
	 * @return int|false
	 */
	public static function verify_time_token( $token ) {
		if ( ! is_string( $token ) || false === strpos( $token, '.' ) ) {
			return false;
		}
		$parts = explode( '.', $token, 2 );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) ) {
			return false;
		}
		$ts       = (int) $parts[0];
		$expected = substr( hash_hmac( 'sha256', (string) $ts, wp_salt( 'nonce' ) ), 0, 16 );
		if ( ! hash_equals( $expected, (string) $parts[1] ) ) {
			return false;
		}
		return $ts;
	}

	/**
	 * Return the hidden honeypot + time-trap HTML markup.
	 *
	 * @return string
	 */
	public function get_honeypot_html() {
		$settings   = WPFH_HPS_Settings::get();
		$field_name = $settings['honeypot_field_name'];
		$token      = self::generate_time_token();

		$html  = '<div class="wpfh-hps-field" aria-hidden="true" style="position:absolute !important;left:-9999px !important;top:-9999px !important;width:1px !important;height:1px !important;overflow:hidden !important;opacity:0 !important;pointer-events:none !important;">';
		$html .= '<label for="' . esc_attr( $field_name ) . '">' . esc_html__( 'Leave this field empty', 'forgehub-honeypot-shield' ) . '</label>';
		$html .= '<input type="text" id="' . esc_attr( $field_name ) . '" name="' . esc_attr( $field_name ) . '" value="" tabindex="-1" autocomplete="off" />';
		$html .= '<input type="hidden" name="wpfh_hps_token" value="' . esc_attr( $token ) . '" />';
		$html .= '</div>';

		return $html;
	}

	/**
	 * Echo the honeypot fields into a WordPress form.
	 *
	 * @return void
	 */
	public function render_honeypot_fields() {
		if ( $this->should_bypass() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- All attributes and labels are escaped in get_honeypot_html().
		echo $this->get_honeypot_html();
	}

	/**
	 * Determine whether the current request should bypass honeypot checks.
	 *
	 * @return bool
	 */
	public function should_bypass() {
		$settings = WPFH_HPS_Settings::get();
		if ( ! empty( $settings['bypass_logged_in_admins'] ) && is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return true;
		}

		/**
		 * Allow extensions (e.g. Pro IP allowlist) to bypass honeypot validation.
		 *
		 * @param bool $bypass Default false.
		 */
		return (bool) apply_filters( 'wpfh_hps_should_bypass', false );
	}

	/**
	 * Validate a POST payload against honeypot + time-trap rules.
	 *
	 * @param array  $payload Submitted POST array.
	 * @param string $surface Surface identifier.
	 * @param array  $context Optional context (email, content, author).
	 * @return array { 'blocked' => bool, 'reason' => string }
	 */
	public function check_submission( $payload, $surface, $context = array() ) {
		if ( $this->should_bypass() ) {
			return array(
				'blocked' => false,
				'reason'  => '',
			);
		}

		$settings   = WPFH_HPS_Settings::get();
		$field_name = $settings['honeypot_field_name'];

		// 1. Honeypot trap field filled by bot.
		if ( isset( $payload[ $field_name ] ) && '' !== trim( (string) $payload[ $field_name ] ) ) {
			return $this->trigger_block( $surface, 'honeypot_filled', $context );
		}

		// 2. Signed time-trap validation.
		$min_sec = (int) $settings['min_submit_seconds'];
		$max_age = (int) $settings['max_token_age_seconds'];
		$token   = isset( $payload['wpfh_hps_token'] ) ? sanitize_text_field( (string) $payload['wpfh_hps_token'] ) : '';

		if ( '' === $token ) {
			return $this->trigger_block( $surface, 'missing_token', $context );
		}

		$ts = self::verify_time_token( $token );
		if ( false === $ts ) {
			return $this->trigger_block( $surface, 'invalid_token', $context );
		}

		$elapsed = time() - $ts;
		if ( $min_sec > 0 && $elapsed < $min_sec ) {
			return $this->trigger_block( $surface, 'submitted_too_fast', $context );
		}

		if ( $max_age > 0 && $elapsed > $max_age ) {
			return $this->trigger_block( $surface, 'token_expired', $context );
		}

		/**
		 * Allow Pro rules (keyword blacklist, max links, disposable emails) to inspect submission.
		 *
		 * @param array  $result  Default unblocked result.
		 * @param string $surface Surface name.
		 * @param array  $context Submission context.
		 */
		$ext_result = apply_filters(
			'wpfh_hps_extra_validation',
			array(
				'blocked' => false,
				'reason'  => '',
			),
			$surface,
			$context
		);

		if ( ! empty( $ext_result['blocked'] ) ) {
			return $this->trigger_block(
				$surface,
				! empty( $ext_result['reason'] ) ? sanitize_key( (string) $ext_result['reason'] ) : 'pro_rule',
				$context
			);
		}

		return array(
			'blocked' => false,
			'reason'  => '',
		);
	}

	/**
	 * Record block stats and fire notification hook.
	 *
	 * @param string $surface Surface key.
	 * @param string $reason  Block reason key.
	 * @param array  $context Optional context.
	 * @return array
	 */
	private function trigger_block( $surface, $reason, $context = array() ) {
		WPFH_HPS_Settings::record_block( $surface );

		/**
		 * Fires whenever Honeypot Shield blocks a spam submission.
		 *
		 * @param string $surface Surface key.
		 * @param string $reason  Reason code.
		 * @param array  $context Submission context.
		 */
		do_action( 'wpfh_hps_spam_blocked', $surface, $reason, $context );

		return array(
			'blocked' => true,
			'reason'  => $reason,
		);
	}

	/**
	 * Validate WordPress comment submissions.
	 *
	 * @param array $commentdata Comment data array.
	 * @return array
	 */
	public function validate_comment( $commentdata ) {
		if ( is_admin() ) {
			return $commentdata;
		}

		$type = isset( $commentdata['comment_type'] ) ? (string) $commentdata['comment_type'] : '';
		if ( in_array( $type, array( 'pingback', 'trackback' ), true ) ) {
			return $commentdata;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core comment form handles its own nonce; honeypot checks raw bot POST payload.
		$payload = wp_unslash( $_POST );
		$context = array(
			'email'   => isset( $commentdata['comment_author_email'] ) ? (string) $commentdata['comment_author_email'] : '',
			'author'  => isset( $commentdata['comment_author'] ) ? (string) $commentdata['comment_author'] : '',
			'content' => isset( $commentdata['comment_content'] ) ? (string) $commentdata['comment_content'] : '',
		);

		$check = $this->check_submission( $payload, 'comments', $context );
		if ( ! empty( $check['blocked'] ) ) {
			$settings = WPFH_HPS_Settings::get();
			if ( 'spam' === $settings['comment_action'] ) {
				$this->flag_comment_as_spam = true;
			} else {
				wp_die(
					esc_html( $settings['block_message'] ),
					esc_html__( 'Spam Protection', 'forgehub-honeypot-shield' ),
					array(
						'response'  => 403,
						'back_link' => true,
					)
				);
			}
		}

		return $commentdata;
	}

	/**
	 * Force spam status when comment_action is set to 'spam'.
	 *
	 * @param int|string|WP_Error $approved    Current approval status.
	 * @param array               $commentdata Comment data.
	 * @return int|string|WP_Error
	 */
	public function filter_comment_approved( $approved, $commentdata ) {
		if ( $this->flag_comment_as_spam ) {
			$this->flag_comment_as_spam = false;
			return 'spam';
		}
		return $approved;
	}

	/**
	 * Validate WordPress registration form.
	 *
	 * @param WP_Error $errors               Registration errors.
	 * @param string   $sanitized_user_login Username.
	 * @param string   $user_email           Email.
	 * @return WP_Error
	 */
	public function validate_registration( $errors, $sanitized_user_login, $user_email ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core registration form validation hook.
		$payload = wp_unslash( $_POST );
		$context = array(
			'email'  => (string) $user_email,
			'author' => (string) $sanitized_user_login,
		);

		$check = $this->check_submission( $payload, 'registration', $context );
		if ( ! empty( $check['blocked'] ) ) {
			$settings = WPFH_HPS_Settings::get();
			$errors->add( 'wpfh_hps_spam', $settings['block_message'] );
		}

		return $errors;
	}

	/**
	 * Validate WordPress login form (only on POST login submissions).
	 *
	 * @param WP_User|WP_Error|null $user     Current auth result.
	 * @param string                $username Username.
	 * @param string                $password Password.
	 * @return WP_User|WP_Error|null
	 */
	public function validate_login( $user, $username, $password ) {
		if ( '' === (string) $username && '' === (string) $password ) {
			return $user;
		}

		// Only enforce on standard wp-login.php form POSTs (do not break XML-RPC/REST/programmatic auth).
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Login form POST detection.
		if ( ! isset( $_POST['wp-submit'] ) && ! isset( $_POST['wpfh_hps_token'] ) ) {
			return $user;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Login form honeypot validation.
		$payload = wp_unslash( $_POST );
		$context = array(
			'author' => (string) $username,
		);

		$check = $this->check_submission( $payload, 'login', $context );
		if ( ! empty( $check['blocked'] ) ) {
			$settings = WPFH_HPS_Settings::get();
			return new WP_Error( 'wpfh_hps_spam', $settings['block_message'] );
		}

		return $user;
	}

	/**
	 * Validate WordPress lost password form.
	 *
	 * @param WP_Error      $errors    Errors object.
	 * @param WP_User|false $user_data User object or false.
	 * @return void
	 */
	public function validate_lostpassword( $errors, $user_data = false ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Lost password form honeypot validation.
		$payload = wp_unslash( $_POST );
		$context = array(
			'email' => ( $user_data instanceof WP_User ) ? $user_data->user_email : '',
		);

		$check = $this->check_submission( $payload, 'lostpassword', $context );
		if ( ! empty( $check['blocked'] ) ) {
			$settings = WPFH_HPS_Settings::get();
			$errors->add( 'wpfh_hps_spam', $settings['block_message'] );
		}
	}
}
