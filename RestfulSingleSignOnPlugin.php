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
		/**
		 * The authentication interface
		 *
		 * @var RestfulSingleSignOn_Api_AuthInterface
		 */
		protected $_auth_interface;

		protected $_backup_mailer;
		
		public function __construct()
		{
			add_action('admin_init', array($this, 'event_admin_init'));
			add_action('admin_menu', array($this, 'event_admin_menu'));
			add_filter('allow_password_reset', array($this,'can_user_reset_password'), 30, 2);
			add_filter('authenticate', array($this, 'wp_authenticate_username_password'), 25, 3);
			add_filter('show_password_fields', array($this,'can_user_change_password'), 30, 2);
		}

		/**
		 * Get the authentication interface.
		 *
		 * @return RestfulSingleSignOn_Api_AuthInterface
		 */
		protected function _getAuthInterface()
		{
			if (empty($this->_auth_interface)) {
				$interface = new RestfulSingleSignOn_Api_Rest(
					get_option('restful-single-signon-auth-endpoint'),
					get_option('restful-single-signon-auth-password-reset-endpoint'),
					get_option('restful-single-signon-auth-resource'),
					get_option('restful-single-signon-auth-resource-username'),
					get_option('restful-single-signon-auth-resource-password'),
					get_option('restful-single-signon-auth-resource-email'),
					get_option('restful-single-signon-auth-resource-first_name'),
					get_option('restful-single-signon-auth-resource-last_name'),
					get_option('restful-single-signon-auth-error-property')
				);
				$this->_auth_interface = apply_filters('restful_single_sign_on_auth_interface', $interface);
			}
			return $this->_auth_interface;
		}

		/**
		 * Callback for the WordPress admin_init action.
		 */
		public function event_admin_init()
		{
			add_settings_section(
				'restful-single-signon-auth-settings-section-id',
				__('Endpoint Settings', 'restful-single-sign-on' ),
				array($this, 'print_settings_section'),
				'restful-single-signon-auth-settings-page'
			);

			add_settings_field(
				'restful-single-signon-auth-endpoint',
				__('Authentication Endpoint', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_endpoint'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-password-reset-endpoint',
				__('Password Reset Endpoint', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_password_reset_endpoint'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource',
				__('Authenticated Resource', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_resource'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-username',
				__('Resource Username', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_resource_username'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-password',
				__('Resource Password', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_resource_password'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-email',
				__('Resource Email', 'restful-single-sign-on' ),
				array($this, 'print_setting_auth_resource_email'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-first_name',
				__('Resource First Name', 'restful-single-sign-on'),
				array($this, 'print_setting_auth_resource_first_name'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-resource-last_name',
				__('Resource Last Name', 'restful-single-sign-on'),
				array($this, 'print_setting_auth_resource_last_name'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			add_settings_field(
				'restful-single-signon-auth-error-property',
				__('Response Error Property', 'restful-single-sign-on'),
				array($this, 'print_setting_auth_error_property'),
				'restful-single-signon-auth-settings-page',
				'restful-single-signon-auth-settings-section-id'
			);

			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-endpoint');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-password-reset-endpoint');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-username');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-password');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-email');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-first_name');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-resource-last_name');
			register_setting('restful-single-signon-auth-options-group', 'restful-single-signon-auth-error-property');
		}

		/**
		 * Callback for the WordPress admin_menu action.
		 */
		public function event_admin_menu()
		{
			add_submenu_page(
				'options-general.php',
				__('Single Sign-On Settings', 'restful-single-sign-on'),
				__('Single Sign-On Settings', 'restful-single-sign-on'),
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
		 * Print the markup for the SSO auth password reset endpoint setting field.
		 */
		public function print_setting_auth_password_reset_endpoint()
		{
			$setting = get_option('restful-single-signon-auth-password-reset-endpoint');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-password-reset-endpoint" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php _e('The password reset endpoint. Leave blank to disable password reset for users authenticated RESTfully.', 'restful-single-sign-on' ) ?></span>
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
		 * Print the markup for the SSO auth error response property.
		 */
		public function print_setting_auth_error_property()
		{
			$setting = get_option('restful-single-signon-auth-error-property');
			?>
			<label>
				<input type="text" name="restful-single-signon-auth-error-property" value="<?php echo esc_attr( $setting ); ?>" />
				<span><?php printf(__('The response\'s error property, which is typically something like %s', 'restful-single-sign-on' ), '<code>error</code>') ?></span>
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
				$error_property = get_option('restful-single-signon-auth-error-property');
				$first_name_property = get_option('restful-single-signon-auth-resource-first_name');
				$last_name_property = get_option('restful-single-signon-auth-resource-last_name');
				$email_property = get_option('restful-single-signon-auth-resource-email');

				// Already a corresponding WordPress user
				if ($db_user instanceof WP_User) {
					if ($db_user->get('restful_sso_user')) {
						$data = $this->_getAuthInterface()->authenticateUser($username, $password);
						if (!$data instanceof WP_Error) {
							$user = $db_user;
						}
					}

				} else {
					$data = $this->_getAuthInterface()->authenticateUser($username, $password);
					if (!$data instanceof WP_Error) {
						// Let's create a user in the WordPress system corresponding to the user.
						$arbitrary_password = sha1(uniqid(microtime()));
						$user_id = wp_create_user($username, $arbitrary_password, $data[$email_property]);
						update_user_meta($user_id, 'first_name', $data[$first_name_property]);
						update_user_meta($user_id, 'last_name', $data[$last_name_property]);
						update_user_meta($user_id, 'restful_sso_user', true);

						$user = get_user_by('id', $user_id);
					}
				}
			}
			return $user;
		}

		/**
		 * A callback filter to determine whether the user is allowed to reset
		 * the password.
		 *
		 * @param boolean $allowed The current determination of whether the user is allowed to reset the password.
		 * @param integer $user_id The Id of the user in question.
		 *
		 * @return boolean Whether the user can reset her password.
		 */
		public function can_user_reset_password($allowed = true, $user_id = 0)
		{
			global $phpmailer;

			// We don't want to allow a user that has been disallowed elsewhere.
			if ($allowed) {
				$is_restful_user = (bool) get_user_meta($user_id, 'restful_sso_user');
				if ($is_restful_user) {
					$have_reset_endpoint = get_option('restful-single-signon-auth-password-reset-endpoint');
					$have_reset_endpoint = ! empty($have_reset_endpoint);
					$allowed = (bool) ($is_restful_user && $have_reset_endpoint);
					if ($allowed) {
						$this->_backup_mailer = $phpmailer;
						$user = get_user_by('id', $user_id);
						if ($user instanceof WP_User) {
							$username = $user->user_email;
							$result = $this->_getAuthInterface()->requestPasswordReset($username);
							if ($result instanceof WP_Error) {
								$phpmailer = new RestfulSingleSignOn_DummyMailer(false, $result);
							} else {
								$phpmailer = new RestfulSingleSignOn_DummyMailer(false, true);
							}
						}
					}
				}
			}
			return $allowed;
		}

		/**
		 * Determine whether the user can see the change password fields in the user admin,
		 * which should not happen for users who are managed by the RESTful API.
		 *
		 * @param boolean $allowed Whether WordPress has determined thus far that the user can change the password.
		 * @param WP_User $user    The user in question.
		 *
		 * @return boolean Whether the user can see the profile change password fields.
		 */
		public function can_user_change_password($allowed = true, $user = null)
		{
			if ($user instanceof WP_User) {
				$is_restful_user = (bool) get_user_meta($user->ID, 'restful_sso_user');
				$allowed = ! $is_restful_user;
			}
			return $allowed;
		}
	}

	/**
	 * Initialize the plugin into a global.
	 */
	function initialize_restful_single_sign_on_plugin()
	{
		global $restful_single_sign_on_plugin;
		$restful_single_sign_on_plugin = new RestfulSingleSignOnPlugin();
	}

	/**
	 * Autoload classes used in this plugin.
	 *
	 * @param string $class The unknown class that PHP is looking for.
	 */
	function single_sign_on_plugin_autoloader($class = '')
	{
		if (preg_match('/^restfulsinglesignon_(.*)/i',$class, $matches) && $matches[1]) {
			$subdirs = explode('_', $matches[1]);
			$class_file = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'RestfulSingleSignOn';
			foreach($subdirs as $sub) {
				$class_file .= DIRECTORY_SEPARATOR . $sub;
			}
			$class_file .= '.php';
			if (file_exists($class_file)) {
				include_once $class_file;
			}
		}
	}

	add_action('plugins_loaded', 'initialize_restful_single_sign_on_plugin');

	spl_autoload_register('single_sign_on_plugin_autoloader');
}
