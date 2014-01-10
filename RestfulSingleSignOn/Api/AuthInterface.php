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

	/**
	 * Request current user info.
	 *
	 * @param string $session_id The Id of the session to send for authentication.
	 *
	 * @return RestfulSingleSignOn_HttpResponse The HTTP response.
	 */
	public function getCurrentUserInfo($session_id);
}
