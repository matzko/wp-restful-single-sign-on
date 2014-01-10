<?php

class RestfulSingleSignOn_Api_Rest
implements RestfulSingleSignOn_Api_AuthInterface
{
	protected $_auth_endpoint;
	protected $_password_reset_endpoint;
	protected $_resource_name;
	protected $_resource_username;
	protected $_resource_password;
	protected $_resource_email;
	protected $_resource_first_name;
	protected $_resource_last_name;
	protected $_error_property;

	/**
	 * Constructor
	 *
	 * @param string $auth_endpoint           The main endpoint to which the auth credentials should be sent.
	 * @param string $password_reset_endpoint The endpoint to which a request to reset the password should be sent.
	 * @param string $resource_name           The name of the resource at the RESTful API, such as "user."
	 * @param string $resource_username       The name of the username property for the resource.
	 * @param string $resource_password       The name of the password property for the resource.
	 * @param string $resource_email          The name of the email property for the resource.
	 * @param string $resource_first_name     The name of the first name property for the resource.
	 * @param string $resource_last_name      The name of the last name property for the resource.
	 * @param string $error_property          The name of the error property in the response.
	 */
	public function __construct(
		$auth_endpoint = '',
		$password_reset_endpoint = '',
		$resource_name = '',
		$resource_username = '',
		$resource_password = '',
		$resource_email = '',
		$resource_first_name = '',
		$resource_last_name = '',
		$error_property = ''
	) {
		$this->_auth_endpoint = $auth_endpoint;
		$this->_password_reset_endpoint = $password_reset_endpoint;
		$this->_resource_name = $resource_name;
		$this->_resource_username = $resource_username;
		$this->_resource_password = $resource_password;
		$this->_resource_email = $resource_email;
		$this->_resource_first_name = $resource_first_name;
		$this->_resource_last_name = $resource_last_name;
		$this->_error_property = $error_property;
	}

	/**
	 * Make a remote RESTful request.
	 *
	 * @param string $endpoint The endpoint to which to make the request.
	 * @param array  $data     The data to send to the request.
	 *
	 * @result array The response to the request.
	 */
	protected function _make_request($endpoint, $data = array())
	{
		$result = wp_remote_post(
			$endpoint, 
			array(
				'headers' => array(
					'Accept' => 'application/json',
					'Content-type' => 'application/json'
				),
				'body' => json_encode($data),
			)
		);
		return $result;
	}

	/**
	 * Authenticate a user with the given credentials.
	 *
	 * @param string $username The username of the user to authenticate.
	 * @param string $password The password of the user to authenticate.
	 *
	 * @return array|WP_Error The array of user properties if successful; error otherwise.
	 */
	public function authenticateUser($username, $password)
	{
		$response = $this->_make_request($this->_auth_endpoint, array(
			$this->_resource_name => array(
				$this->_resource_username => $username,
				$this->_resource_password => $password,
			),
		));
		$result = RestfulSingleSignOn_HttpResponse::buildFromWordPressResponse($response);
		return $result;
	}

	/**
	 * Request that the given user receive a password reset.
	 *
	 * @param string $username The username of the user for whom to reset the password.
	 *
	 * @return array|WP_Error The array of user properties if successful; error otherwise.
	 */
	public function requestPasswordReset($username)
	{
		$response = $this->_make_request($this->_password_reset_endpoint, array(
			$this->_resource_name => array(
				$this->_resource_username => $username,
			),
		));
		$result = RestfulSingleSignOn_HttpResponse::buildFromWordPressResponse($response);
		return $result;
	}
}
