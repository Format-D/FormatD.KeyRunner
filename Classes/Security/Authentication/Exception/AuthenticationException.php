<?php

namespace FormatD\KeyRunner\Security\Authentication\Exception;

use Throwable;

enum AuthenticationError: string
{
    case ProviderNotFound = 'provider_not_found';
    case InvalidOTP = 'invalid_otp';
    case AuthenticationFailed = 'authentication_failed';
	case AccountCreationFailed = 'account_creation_failed';
	case OTPGenerationFailed = 'otp_generation_failed';
    case MailSendingFailed = 'mail_sending_failed';
}


class AuthenticationException extends \Exception
{
    public function __construct(AuthenticationError $errorType, string $message = "", int $code = 0, Throwable $previous = null)
    {
        $message = $message ?: $this->getErrorMessage($errorType);
        parent::__construct($message, $code, $previous);
    }

    private function getErrorMessage(AuthenticationError $errorType): string
    {
        $messages = [
            AuthenticationError::ProviderNotFound->value => 'Provider not found.',
            AuthenticationError::InvalidOTP->value => 'Ungültiger Code.',
            AuthenticationError::AuthenticationFailed->value => 'Authentifizierung fehlgeschlagen.',
        ];

        return $messages[$errorType->value] ?? 'Unknown error.';
    }
}
