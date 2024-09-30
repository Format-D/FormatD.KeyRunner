<?php

namespace FormatD\KeyRunner\Controller;

use FormatD\KeyRunner\Domain\TokenHandler;
use FormatD\KeyRunner\Security\Authentication\Exception\AuthenticationError;
use FormatD\KeyRunner\Security\Authentication\Exception\AuthenticationException;
use Neos\Flow\Security\Account;

abstract class MailDeliveryMethodFrontendController extends DeliveryMethodFrontendController
{
	public function prepareInputAction(string $providerName, string $id, ?string $redirectUri = null, ?string $redirectHash = null)
	{
		$this->sendMailWithTOTP($providerName, $id);
		$this->redirect("showInput", arguments: ["id" => $id, "providerName" => $providerName, 'redirectUri' => $redirectUri, "redirectHash" => $redirectHash]);
	}

    public function retryAction(string $providerName, string $id)
	{

        $this->sendMailWithTOTP($providerName, $id);
		$this->addFlashMessage('Der Code wurde erneut an die von Ihnen hinterlegte E-Mail-Adresse gesendet.', 'Code erneut gesendet.');
        $this->redirect("showInput", arguments: ["id" => $id, "providerName" => $providerName]);
    }

    protected function sendMailWithTOTP(string $providerName, string $id)
    {
		$deliveryMethod = $this->getTokenHandlerByProviderName($providerName);

		if ($deliveryMethod === null) {
			return;
		}

        $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($id, $providerName);
        $currentOneTimePassword = $deliveryMethod->generateCurrentOneTimePasswordForAccount($account);
        if($currentOneTimePassword === null) {
            throw new AuthenticationException(AuthenticationError::OTPGenerationFailed, 'Could not generate a one-time password.');
        }
        // TODO: create some kind of MailSenderInterface or a Concrete Class of this and pass $account,
		// 		 $deliveryMethod and $currentOneTimePassword to `->sendCurrentOneTimePassword` method
		try {
			$this->sendMail($account, $deliveryMethod, $currentOneTimePassword);
		} catch (\Exception $th) {
			throw new AuthenticationException(AuthenticationError::MailSendingFailed, 'Could not send one-time password mail.');
		}
    }
	protected function createTOTPDataForShowInput(string $providerName, string $id): array
	{
		$data = parent::createTOTPDataForShowInput($providerName, $id);
		$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($id, $providerName);
		$data['recipientEmailAddress'] = $this->getRecipientEmailAddress($account, $this->getTokenHandlerByProviderName($providerName));
		return $data;
	}

	protected function getTokenHandlerByProviderName(string $providerName): ?TokenHandler
	{
		$provider = $this->TOTPService->getProvider($providerName);
        if(!$provider) {
            return null;
        }
		$deliveryMethod = $provider->getDeliveryMethod();
		return $deliveryMethod;
	}
    abstract protected function sendMail(Account $account, TokenHandler $deliveryMethod, string $currentOneTimePassword);

	abstract protected function getRecipientEmailAddress(Account $account, TokenHandler $deliveryMethod): string;
}
