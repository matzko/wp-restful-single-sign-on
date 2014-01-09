<?php
require_once ABSPATH . WPINC . '/class-phpmailer.php';
require_once ABSPATH . WPINC . '/class-smtp.php';

/**
 * The purpose of this class is to temporarily override
 * WordPress's sending of the reset password info,
 * for those users whose reset should come from the 
 * RESTful resource.
 */
class RestfulSingleSignOn_DummyMailer extends PHPMailer 
{
	protected $_sendReturn;
	public function __construct($exceptions = false, $sendReturnValue = null)
	{
		$this->_sendReturn = $sendReturnValue;
		parent::__construct($exceptions);
	}
	public function Send()
	{
		return $this->_sendReturn;
	}
}
