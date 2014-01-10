<?php

interface RestfulSingleSignOn_Api_AuthInterface
{
	/**
	 * Authenticate a user with the given credentials.
	 *
	 * @param string $username The username of the user to authenticate.
	 * @param string $password The password of the user to authenticate.
	 *
	 * @return RestfulSingleSignOn_HttpResponse The HTTP response.
	 */
	public function authenticateUser($username, $password);

	/**
	 * Request that the given user receive a password reset.
	 *
	 * @param string $username The username of the user for whom to reset the password.
	 *
	 * @return RestfulSingleSignOn_HttpResponse The HTTP response.
	 */
	public function requestPasswordReset($username);
}
