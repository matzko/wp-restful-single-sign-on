<?php
/*
Plugin Name: RESTful Single Sign-On
Plugin URI: https://github.com/matzko/wp-restful-single-sign-on
Description: Single Sign-On (SSO) with a RESTful identity provider. 
Author: Austin Matzko
Author URI: https://austinmatzko.com
Version: 1.0
Text Domain: restful-single-sign-on
*/

if (! class_exists('RestfulSingleSignOnPlugin')) {
	class RestfulSingleSignOnPlugin
	{
		public function __construct()
		{
			add_filter('authenticate', array($this, 'wp_authenticate_username_password'), 25, 3);
			add_action('admin_init', array($this, 'event_admin_init'));
			add_action('admin_menu', array($this, 'event_admin_menu'));
		}

		/**
		 * Callback for the WordPress admin_init action.
		 */
		public function event_admin_init()
		{
			add_settings_section(
				'restful-single-signon-auth-settings-section-id',
				__( 'Endpoint Settings', 'restful-single-sign-on' ),
				array($this, 'print_settings_section'),
				'restful-single-signon-auth-settings-page'
			);

			add_settings_field(
				'restful-single-signon-auth-endpoint',
				__( 'Authentication Endpoint', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_endpoint'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource',
				__( 'Authenticated Resource', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_resource'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-username',
				__( 'Resource Username', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_resource_username'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-password',
				__( 'Resource Password', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_resource_password'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-email',
				__( 'Resource Email', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_resource_email'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-first_name',
				__( 'Resource First Name', 'restful-single-sign-on'),
				array($this, 'print_setting_auth_resource_first_name'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-last_name',
				__( 'Resource Last Name', 'restful-single-sign-on'),
				array($this, 'print_setting_auth_resource_last_name'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-endpoint');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-username');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-password');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-email');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-first_name');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-last_name');
		}

		/**
		 * Callback for the WordPress admin_menu action.
		 */
		public function event_admin_menu()
		{
			add_submenu_page(
				'options-general.php',
				__('Sign-On Settings', 'restful-single-sign-on'),
				__('Sign-On Settings', 'restful-single-sign-on'),
				'manage_options',
				'restful-single-sign-on-settings',
				array($this, 'print_settings')
			);
		}

		/**
		 * Print the markup for the SSO auth endpoint setting field.
		 */
		public function print_setting_auth_endpoint()
		{
			$setting = get_option('restful-single-signon-auth-endpoint');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-endpoint" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php printf(__('The sign-in endpoint, which is typically something like %s', 'restful-single-sign-on' ), '<code>http://your-site.com/users/sign_in</code>') ?></span>
			</label>
			<?php
		}

		/**
		 * Print the markup for the SSO auth resource setting field.
		 */
		public function print_setting_auth_resource()
		{
			$setting = get_option('restful-single-signon-auth-resource');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-resource" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php printf(__('The authenticated resource, which is typically something like %s', 'restful-single-sign-on' ), '<code>user</code>') ?></span>
			</label>
			<?php
		}

		/**
		 * Print the markup for the SSO auth resource username field.
		 */
		public function print_setting_auth_resource_username()
		{
			$setting = get_option('restful-single-signon-auth-resource-username');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-resource-username" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php printf(__('The resource\'s username, which is typically something like %s', 'restful-single-sign-on' ), '<code>email</code>') ?></span>
			</label>
			<?php
		}

		/**
		 * Print the markup for the SSO auth resource password field.
		 */
		public function print_setting_auth_resource_password()
		{
			$setting = get_option('restful-single-signon-auth-resource-password');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-resource-password" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php printf(__('The resource\'s password property, which is typically something like %s', 'restful-single-sign-on' ), '<code>password</code>') ?></span>
			</label>
			<?php
		}

		/**
		 * Print the markup for the SSO auth resource email field.
		 */
		public function print_setting_auth_resource_email()
		{
			$setting = get_option('restful-single-signon-auth-resource-email');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-resource-email" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php printf(__('The resource\'s email property, which is typically something like %s', 'restful-single-sign-on' ), '<code>email</code>') ?></span>
			</label>
			<?php
		}

		/**
		 * Print the markup for the SSO auth resource first name field.
		 */
		public function print_setting_auth_resource_first_name()
		{
			$setting = get_option('restful-single-signon-auth-resource-first_name');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-resource-first_name" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php printf(__('The resource\'s first name property, which is typically something like %s', 'restful-single-sign-on' ), '<code>first_name</code>') ?></span>
			</label>
			<?php
		}

		/**
		 * Print the markup for the SSO auth resource last name field.
		 */
		public function print_setting_auth_resource_last_name()
		{
			$setting = get_option('restful-single-signon-auth-resource-last_name');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-resource-last_name" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php printf(__('The resource\'s last name property, which is typically something like %s', 'restful-single-sign-on' ), '<code>last_name</code>') ?></span>
			</label>
			<?php
		}

		/**
		 * Print the settings section.
		 */
		public function print_settings_section()
		{
			settings_fields('restful-single-signon-auth-options-group');
		}
		
		/**
		 * Print the settings form.
		 */
		public function print_settings()
		{
			?>
			<div class="wrap">
				<h2><?php _e('Sign-On Settings', 'restful-single-sign-on' ); ?></h2>
				<form action="<?php echo admin_url('options.php'); ?>" method="post">
					<?php do_settings_sections('restful-single-signon-auth-settings-page'); ?>
					<p class="submit">
						<input type="submit" name="submit" class="button-primary" value="<?php esc_attr_e('Save Settings', 'restful-single-sign-on'); ?>" />
					</p>
				</form>
			</div><!-- .wrap -->
			<?php
		}

		public function wp_authenticate_username_password($user, $username, $password)
		{
			if (
				($user instanceof WP_Error)
				&& (!empty($username))
				&& (!empty($password))
			) {
				$db_user = get_user_by('login', $username);

				// Already a corresponding WordPress user
				if ($db_user instanceof WP_User) {
					if ($db_user->get('restful_sso_user')) {
						$data = $this->get_userdata_from_sso_credentials($username, $password);
						// This indicates that the password has been correctly submitted
						// but is different from the WordPress password, so we need to update 
						// the WP password
						if ($data['is_valid']) {
							wp_set_password($password, $db_user->ID);
							$user = $db_user;
						}
					}

				} else {
					$data = $this->get_userdata_from_sso_credentials($username, $password);
					if ($data['is_valid']) {
						// Let's create a user in the WordPress system corresponding to the user.
						$user_id = wp_create_user($username, $password, $data['email']);
						update_user_meta($user_id, 'first_name', $data['first_name']);
						update_user_meta($user_id, 'last_name', $data['last_name']);
						update_user_meta($user_id, 'restful_sso_user', true);

						$user = get_user_by('id', $user_id);
					}
				}
			}
			return $user;
		}

		/**
		 * Get the user data for the user, given her credentials.
		 *
		 * @param [String] $username The username of the user.
		 * @param [String] $password The password of the user.
		 *
		 * @return mixed The array of user data or null if none found.
		 */
		protected function get_userdata_from_sso_credentials($username, $password)
		{
			$data = null;
			$endpoint = get_option('restful-single-signon-auth-endpoint');
			if (!empty($endpoint)) {
				$result = wp_remote_post(
					$endpoint, 
					array(
						'headers' => array('Accept' => 'application/json', 'Content-type' => 'application/json'),
						'body' => json_encode(array(
							'user' => array(
								'email' => $username,
								'password' => $password,
							),
						)),
					)
				);
				$data = empty($result['body']) ? null : json_decode($result['body'], true);
			}
			return $data;
		}
	}

	function initialize_restful_single_sign_on_plugin()
	{
		global $restful_single_sign_on_plugin;
		$restful_single_sign_on_plugin = new RestfulSingleSignOnPlugin();
	}

	add_action('plugins_loaded', 'initialize_restful_single_sign_on_plugin');
}
