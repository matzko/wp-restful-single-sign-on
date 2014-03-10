<?php
/**
 * This class represents the responses from an HTTP request.
 */
class RestfulSingleSignOn_HttpResponse
{
	/**
	 * The request type.
	 *
	 * @var string 
	 */
	protected $_request_type;

	/**
	 * Response code
	 *
	 * @var string
	 */
	protected $_response_code;

	/**
	 * Response message
	 *
	 * @var string
	 */
	protected $_response_message;

	/**
	 * The header values.
	 *
	 * @var array
	 */
	protected $_headers = array();

	/**
	 * The cookies, if any.
	 *
	 * @var array[WP_Http_Cookie]
	 */
	protected $_cookies = array();

	/**
	 * Raw body response.
	 *
	 * @var string
	 */
	protected $_raw_resp_body;

	/**
	 * Body as parsed into the appropriate object.
	 *
	 * @var array
	 */
	protected $_parsed_body;

	/**
	 * Constructor
	 *
	 * @param string $raw_response_body The response body.
	 *
	 */
	public function __construct($raw_response_body = '')
	{
		$this->_raw_resp_body = $raw_response_body;
		$data = json_decode($raw_response_body, true);
		if (empty($data['error'])) {
			$this->_parsed_body = $data;
		} else {
			$this->_parsed_body = new WP_Error('request_response',$data['error']);
		}
	}

	/**
	 * Get the raw response body.
	 *
	 * @return string
	 */
	public function getRawResponseBody()
	{
		return $this->_raw_resp_body;
	}

	/**
	 * Get the parsed response body.
	 *
	 * @return array
	 */
	public function getParsedBody()
	{
		return $this->_parsed_body;
	}


	/**
	 * Set the request type.
	 *
	 * @param string $request_type The type of the request.
	 *
	 * @return RestfulSingleSignOn_HttpResponse 
	 */
	public function setRequestType($request_type)
	{
		$this->_request_type = $request_type;
		return $this;
	}

	/**
	 * Get the request type.
	 *
	 * @return string The request type.
	 */
	public function getRequestType()
	{
		return $this->_request_type;
	}

	/**
	 * Set the response code.
	 *
	 * @param string $code
	 *
	 * @return RestfulSingleSignOn_HttpResponse 
	 */
	public function setCode($code)
	{
		$this->_response_code = $code;
		return $this;
	}

	/**
	 * Get the response code.
	 *
	 * @return string
	 */
	public function getCode()
	{
		return $this->_response_code;
	}

	/**
	 * Set the cookies.
	 *
	 * @param array[WP_Http_Cookie] $cookies The cookies.
	 *
	 * @return RestfulSingleSignOn_HttpResponse 
	 */
	public function setCookies($cookies)
	{
		foreach($cookies as $cookie) {
			if ($cookie) {
				$this->_cookies[$cookie->name] = $cookie;
			}
		}
		return $this;
	}

	/** 
	 * Get a particular cookie.
	 *
	 * @param string $name The name of the cookie
	 *
	 * @return WP_Http_Cookie
	 */
	public function getCookie($name)
	{
		$cookie = null;
		if (isset($this->_cookies[$name])) {
			$cookie = $this->_cookies[$name];
		}
		return $cookie;
	}

	/**
	 * Set the headers.
	 *
	 * @param array $headers
	 *
	 * @return RestfulSingleSignOn_HttpResponse 
	 */
	public function setHeaders($headers)
	{
		if (is_array($headers)) {
			$this->_headers = $headers;
		}
		return $this;
	}

	/**
	 * Get the headers
	 *
	 * @return array All the headers.
	 */
	public function getHeaders()
	{
		return $this->_headers;
	}

	/**
	 * Set the response message.
	 *
	 * @param string $message
	 *
	 * @return RestfulSingleSignOn_HttpResponse 
	 */
	public function setMessage($message)
	{
		$this->_response_message = $message;
		return $this;
	}

	/**
	 * Get the response message.
	 *
	 * @return string
	 */
	public function getMessage()
	{
		return $this->_response_message;
	}

	/**
	 * Parse the response from WordPress into an RestfulSingleSignOn_HttpResponse object.
	 *
	 * @param array $wp_response The response from WP
	 *
	 * @return RestfulSingleSignOn_HttpResponse 
	 */
	public static function buildFromWordPressResponse($wp_response)
	{
		$resp = null;
		if (!empty($wp_response) && (!$wp_response instanceof WP_Error)) {
			$body = isset($wp_response['body']) ? $wp_response['body'] : '';
			$resp = new RestfulSingleSignOn_HttpResponse($body);
			if (!empty($wp_response['headers'])) {
				$resp->setHeaders($wp_response['headers']);
			}
			if (!empty($wp_response['cookies'])) {
				$resp->setCookies($wp_response['cookies']);
			}
			if (!empty($wp_response['response']['code'])) {
				$resp->setCode($wp_response['response']['code']);
			}
			if (!empty($wp_response['response']['message'])) {
				$resp->setMessage($wp_response['response']['message']);
			}
		}
		return $resp;
	}
}
