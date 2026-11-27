<?php
/**
 * Uninstall cleanup for ForgeHub Honeypot Shield (Free build).
 *
 * @package ForgeHub_Honeypot_Shield
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wpfh_hps_settings' );
delete_option( 'wpfh_hps_pro_settings' );
delete_option( 'wpfh_hps_stats' );
delete_option( 'wpfh_hps_spam_log' );
delete_option( 'wpfh_hps_review_nudge' );
