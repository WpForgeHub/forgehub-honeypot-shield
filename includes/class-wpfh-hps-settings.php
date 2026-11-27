<?php
/**
 * Settings and statistics manager for ForgeHub Honeypot Shield.
 *
 * @package ForgeHub_Honeypot_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPFH_HPS_Settings
 */
class WPFH_HPS_Settings {

	const OPTION_NAME     = 'wpfh_hps_settings';
	const PRO_OPTION_NAME = 'wpfh_hps_pro_settings';
	const STATS_OPTION    = 'wpfh_hps_stats';

	/**
	 * Default Free settings.
	 *
	 * @return array
	 */
	public static function get_defaults() {
		return array(
			'enabled'                 => true,
			'protect_comments'        => true,
			'protect_registration'    => true,
			'protect_login'           => true,
			'protect_lostpassword'    => true,
			'honeypot_field_name'     => 'wpfh_contact_website_url',
			'min_submit_seconds'      => 3,
			'max_token_age_seconds'   => 3600,
			'comment_action'          => 'reject',
			'block_message'           => 'Your submission could not be verified as human. Please wait a moment and try again.',
			'bypass_logged_in_admins' => true,
		);
	}

	/**
	 * Default Pro settings.
	 *
	 * @return array
	 */
	public static function get_pro_defaults() {
		return array(
			'protect_woocommerce'       => true,
			'protect_cf7'               => true,
			'protect_wpforms'           => true,
			'enable_spam_log'           => true,
			'log_retention_days'        => 30,
			'max_comment_links'         => 0,
			'blocked_keywords'          => '',
			'block_disposable_emails'   => false,
			'disposable_domains'        => "mailinator.com\nguerrillamail.com\ntemp-mail.org\n10minutemail.com\nyopmail.com",
			'ip_allowlist'              => '',
		);
	}

	/**
	 * Get merged Free settings.
	 *
	 * @return array
	 */
	public static function get() {
		$saved = get_option( self::OPTION_NAME, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return wp_parse_args( $saved, self::get_defaults() );
	}

	/**
	 * Get merged Pro settings.
	 *
	 * @return array
	 */
	public static function get_pro() {
		$saved = get_option( self::PRO_OPTION_NAME, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return wp_parse_args( $saved, self::get_pro_defaults() );
	}

	/**
	 * Sanitize Free settings.
	 *
	 * @param mixed $input Raw input.
	 * @return array
	 */
	public static function sanitize( $input ) {
		$defaults = self::get_defaults();
		if ( ! is_array( $input ) ) {
			return $defaults;
		}

		$field_name = isset( $input['honeypot_field_name'] )
			? sanitize_key( (string) $input['honeypot_field_name'] )
			: $defaults['honeypot_field_name'];

		// Prevent collisions with core WordPress form field names.
		$reserved = array( 'author', 'email', 'url', 'comment', 'submit', 'log', 'pwd', 'user_login', 'user_email', 'redirect_to' );
		if ( '' === $field_name || in_array( $field_name, $reserved, true ) ) {
			$field_name = $defaults['honeypot_field_name'];
		}

		$min_sec = isset( $input['min_submit_seconds'] ) ? absint( $input['min_submit_seconds'] ) : $defaults['min_submit_seconds'];
		if ( $min_sec > 30 ) {
			$min_sec = 30;
		}

		$max_age = isset( $input['max_token_age_seconds'] ) ? absint( $input['max_token_age_seconds'] ) : $defaults['max_token_age_seconds'];
		if ( $max_age < 300 ) {
			$max_age = 300;
		} elseif ( $max_age > 86400 ) {
			$max_age = 86400;
		}

		$comment_action = isset( $input['comment_action'] ) ? sanitize_key( (string) $input['comment_action'] ) : 'reject';
		if ( ! in_array( $comment_action, array( 'reject', 'spam' ), true ) ) {
			$comment_action = 'reject';
		}

		$block_msg = isset( $input['block_message'] )
			? sanitize_text_field( (string) $input['block_message'] )
			: $defaults['block_message'];
		if ( '' === $block_msg ) {
			$block_msg = $defaults['block_message'];
		}

		return array(
			'enabled'                 => ! empty( $input['enabled'] ),
			'protect_comments'        => ! empty( $input['protect_comments'] ),
			'protect_registration'    => ! empty( $input['protect_registration'] ),
			'protect_login'           => ! empty( $input['protect_login'] ),
			'protect_lostpassword'    => ! empty( $input['protect_lostpassword'] ),
			'honeypot_field_name'     => $field_name,
			'min_submit_seconds'      => $min_sec,
			'max_token_age_seconds'   => $max_age,
			'comment_action'          => $comment_action,
			'block_message'           => $block_msg,
			'bypass_logged_in_admins' => ! empty( $input['bypass_logged_in_admins'] ),
		);
	}

	/**
	 * Sanitize Pro settings.
	 *
	 * @param mixed $input Raw input.
	 * @return array
	 */
	public static function sanitize_pro( $input ) {
		$defaults = self::get_pro_defaults();
		if ( ! is_array( $input ) ) {
			return $defaults;
		}

		$retention = isset( $input['log_retention_days'] ) ? absint( $input['log_retention_days'] ) : 30;
		if ( $retention < 1 ) {
			$retention = 1;
		} elseif ( $retention > 365 ) {
			$retention = 365;
		}

		$max_links = isset( $input['max_comment_links'] ) ? absint( $input['max_comment_links'] ) : 0;
		if ( $max_links > 50 ) {
			$max_links = 50;
		}

		$keywords = isset( $input['blocked_keywords'] )
			? self::sanitize_multiline_list( (string) $input['blocked_keywords'] )
			: '';

		$domains = isset( $input['disposable_domains'] )
			? self::sanitize_multiline_list( (string) $input['disposable_domains'], true )
			: $defaults['disposable_domains'];

		$ips = isset( $input['ip_allowlist'] )
			? self::sanitize_ip_list( (string) $input['ip_allowlist'] )
			: '';

		return array(
			'protect_woocommerce'     => ! empty( $input['protect_woocommerce'] ),
			'protect_cf7'             => ! empty( $input['protect_cf7'] ),
			'protect_wpforms'         => ! empty( $input['protect_wpforms'] ),
			'enable_spam_log'         => ! empty( $input['enable_spam_log'] ),
			'log_retention_days'      => $retention,
			'max_comment_links'       => $max_links,
			'blocked_keywords'        => $keywords,
			'block_disposable_emails' => ! empty( $input['block_disposable_emails'] ),
			'disposable_domains'      => $domains,
			'ip_allowlist'            => $ips,
		);
	}

	/**
	 * Sanitize newline-separated string list.
	 *
	 * @param string $raw       Raw textarea input.
	 * @param bool   $lowercase Convert lines to lowercase.
	 * @return string
	 */
	private static function sanitize_multiline_list( $raw, $lowercase = false ) {
		$lines = preg_split( '/\r\n|\r|\n/', $raw );
		$clean = array();
		if ( is_array( $lines ) ) {
			foreach ( $lines as $line ) {
				$line = trim( sanitize_text_field( $line ) );
				if ( '' === $line ) {
					continue;
				}
				if ( $lowercase ) {
					$line = strtolower( $line );
				}
				$clean[] = $line;
			}
		}
		return implode( "\n", array_values( array_unique( $clean ) ) );
	}

	/**
	 * Sanitize newline-separated IP list.
	 *
	 * @param string $raw Raw textarea input.
	 * @return string
	 */
	private static function sanitize_ip_list( $raw ) {
		$lines = preg_split( '/\r\n|\r|\n/', $raw );
		$clean = array();
		if ( is_array( $lines ) ) {
			foreach ( $lines as $line ) {
				$line = trim( sanitize_text_field( $line ) );
				if ( '' !== $line && false !== filter_var( $line, FILTER_VALIDATE_IP ) ) {
					$clean[] = $line;
				}
			}
		}
		return implode( "\n", array_values( array_unique( $clean ) ) );
	}

	/**
	 * Return local blocked spam statistics.
	 *
	 * @return array
	 */
	public static function get_stats() {
		$defaults = array(
			'total'        => 0,
			'comments'     => 0,
			'registration' => 0,
			'login'        => 0,
			'lostpassword' => 0,
			'forms'        => 0,
			'last_blocked' => '',
		);
		$saved = get_option( self::STATS_OPTION, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return wp_parse_args( $saved, $defaults );
	}

	/**
	 * Increment blocked spam counter for a surface.
	 *
	 * @param string $surface Surface key (comments, registration, login, lostpassword, forms).
	 * @return void
	 */
	public static function record_block( $surface ) {
		$stats          = self::get_stats();
		$stats['total'] = (int) $stats['total'] + 1;
		$surface_key    = sanitize_key( $surface );

		if ( isset( $stats[ $surface_key ] ) && is_int( $stats[ $surface_key ] ) ) {
			$stats[ $surface_key ] = (int) $stats[ $surface_key ] + 1;
		} else {
			$stats['forms'] = (int) $stats['forms'] + 1;
		}

		$stats['last_blocked'] = gmdate( 'Y-m-d H:i:s' );
		update_option( self::STATS_OPTION, $stats, false );

		$plugin = WPFH_Honeypot_Shield::get_instance();
		if ( $plugin && $plugin->get_review_nudge() ) {
			$plugin->get_review_nudge()->record_success();
		}
	}

	/**
	 * Reset blocked spam counter.
	 *
	 * @return void
	 */
	public static function reset_stats() {
		delete_option( self::STATS_OPTION );
	}
}
