<?php
namespace FormatD\KeyRunner\Security\Authentication\Token;

use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Utility\ObjectAccess;

class OTPToken extends AbstractToken
{
	public const OTP = "otp";
	public const ID = "id";

	protected $credentials = [self::OTP => '', self::ID => ''];

	protected const PROPERTY_PATH = '__authentication.FormatD.KeyRunner.Security.Authentication.Token.OTPToken.';

	public function getOTP(): string
	{
		return $this->credentials[self::OTP];
	}

	public function getId(): string
	{
		return $this->credentials[self::ID];
	}

	public function updateCredentials(ActionRequest $actionRequest)
	{
		$httpRequest = $actionRequest->getHttpRequest();
		if ($httpRequest->getMethod() !== 'POST') {
			return;
		}

		$arguments = $actionRequest->getInternalArguments();
		$otp = ObjectAccess::getPropertyPath($arguments, self::PROPERTY_PATH . self::OTP);
		$id = ObjectAccess::getPropertyPath($arguments, self::PROPERTY_PATH . self::ID);

		if (!empty($otp) && !empty($id)) {
			$this->credentials[self::OTP] = $otp;
			$this->credentials[self::ID] = $id;
			$this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
		}

	}
}
