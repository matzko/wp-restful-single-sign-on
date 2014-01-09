<?php

interface RestfulSingleSignOn_Api_AuthInterface
{
	/**
	 * Authenticate a user with the given credentials.
	 *
	 * @param string $username The username of the user to authenticate.
	 * @param string $password The password of the user to authenticate.
	 *
	 * @return array|WP_Error The array of user properties if successful; error otherwise.
	 */
	public function authenticateUser($username, $password);

	/**
	 * Request that the given user receive a password reset.
	 *
	 * @param string $username The username of the user for whom to reset the password.
	 *
	 * @return array|WP_Error The array of user properties if successful; error otherwise.
	 */
	public function requestPasswordReset($username);
}
