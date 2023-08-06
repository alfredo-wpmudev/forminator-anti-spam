<?php
/**
 * Plugin Name: [Forminator] - Forminator Antispam Shield.
 * Description: [Forminator] - Limit the submition by email, only allow one submit every 24 hours and block IP if try make more than 3 valids submission from the same IP.
 * Author: Alfredo Galano Loyola @ WPMUDEV
 * Author URI: https://wpmudev.com
 * License: GPLv2 or later
 */
require_once('vendor/VerifyEmail.class.php');
if ( ! defined( 'ABSPATH' ) ) {
	exit;
} elseif ( defined( 'WP_CLI' ) && WP_CLI ) {
	return;
}
add_filter( 'forminator_custom_form_submit_errors', function( $submit_errors, $form_id, $field_data_array ){
    //List of forms where you want to use the shield, format [1, 2, 3, 4]
	$list_forms = [1048210];
	//Email field you want to check in the submission, by default it will be email-1,( if you need to check several the code will need some fixes)
    $email_field = 'email-1';
    
    /*
    *Verification settings
    */
    //Only allow one submit per email ON = true / OFF = false
    $unique_submit_by_email = true;
    
    //Block IP if try to make 3 submits from the same IP, only the first one will work, but if keep trying will be blocked if ON = true / OFF = false
    $defender_blacklist = false;
    //Valid email address to perform the email verification
    $smtp_email_tester = 'alfredo.loyola@incsub.com';
    /*
    * Customize your error messages here.
    */
    //Error message for Email used in a previous submit
    $email_error_msg = 'The email already submitted';
    //Error message for fake emails
    $fake_email_error_msg = "This email don't exist!";
    //Error message when try to submit more than one submission in the las 24 hours from the same IP
    $ip_error_msg = 'You cannot submit more than 1 time within 24 hours.';
    //Error message when email is related to temp email, list is common providers in vendor/disposable_email_blocklist.conf
    $disposable_error_msg = "Sorry, we don't accept Disposable Email Address!";

	if( empty($submit_errors) && in_array( $form_id, $list_forms)){
		foreach( $field_data_array as $field ){
			if( $field['name'] === $email_field ){
				global $wpdb;
				$table_meta = $wpdb->prefix . 'frmt_form_entry_meta';
				$table_entry = $wpdb->prefix . 'frmt_form_entry';
				if( $unique_submit_by_email && $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(1) FROM $table_meta as m LEFT JOIN $table_entry as e ON m.entry_id = e.entry_id WHERE m.meta_key = %s AND m.meta_value=%s AND e.form_id = %d LIMIT 1;", $field['name'], $field['value'], $form_id ) ) ){
					$submit_errors[][$email_field] = $email_error_msg;
				}else{
				    $file = file_get_contents('vendor/disposable_email_blocklist.conf', true);
                    $dispossable_domains = explode(PHP_EOL, $file);
                    $curent_email = $pieces = explode("@", $field['value']); 
                    if (in_array($curent_email[1], $dispossable_domains)) {
                        $submit_errors[][$email_field] = $disposable_error_msg;
                    }else{
                        // Initialize library class
                        $mail = new VerifyEmail();
                        
                        // Set the timeout value on stream
                        $mail->setStreamTimeoutWait(1);
                        
                        // Set debug output mode
                        $mail->Debug= FALSE; 
                        $mail->Debugoutput= 'html'; 
                        
                        // Set email address for SMTP request
                        $mail->setEmailFrom($smtp_email_tester);
    
                        // Check if email is valid and exist
                        if(!$mail->check($field['value'])){ 
                            $submit_errors[][$email_field] = $fake_email_error_msg;
                        }
                   
                        
                    }

				}
				
				break;
			}
		}

        if (empty($submit_errors)) {
            $user_ip = Forminator_Geo::get_user_ip();
            if(!empty( $user_ip)){
                $last_entry = Forminator_Form_Entry_Model::get_last_entry_by_ip_and_form( $form_id, $user_ip );

                if (!empty($last_entry)) {
                    $entry        = Forminator_API::get_entry( $form_id, $last_entry );
                    $current_time = strtotime( date( 'Y-m-d H:i:s' ) );
                    $future_time  = strtotime( '+1 day', strtotime( $entry->date_created_sql ) );
                    if ( $current_time < $future_time ) {
                        $cookie_name = 'FORMINATOR_IP_ATTEMPTS_'.$form_id;
                        if(!isset($_COOKIE[$cookie_name])) {
                            setcookie($cookie_name, 1, time() + (86400 * 30), "/");
                            
                        } else {
                            
                            setcookie($cookie_name, $_COOKIE[$cookie_name]+1, time() + (86400 * 30), "/");
                        }
                        $submit_errors[][$email_field]  = $ip_error_msg;
                        
                        if ($defender_blacklist === true && class_exists('WP_Defender\Controller\Blacklist') && $_COOKIE[$cookie_name] > 3 ) {
                            $my_defender = new WP_Defender\Controller\Blacklist;
                            $my_defender->blacklist_an_ip($user_ip);
                            
                        }
                        
                    }
                }
            }
        }
        

	}
	return $submit_errors;
}, 10, 3);