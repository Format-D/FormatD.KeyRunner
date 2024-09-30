<?php


namespace FormatD\KeyRunner\Controller;

use FormatD\KeyRunner\Security\Authentication\Exception\AuthenticationError;
use FormatD\KeyRunner\Security\Authentication\Exception\AuthenticationException;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Party\Domain\Model\AbstractParty;
use Neos\Party\Domain\Repository\PartyRepository;
use Neos\Flow\Annotations as Flow;
use FormatD\KeyRunner\Service\DeliveryMethodService;
use Neos\Flow\Security\Account;
use FormatD\KeyRunner\Service\TOTPService;
use Neos\Flow\Security\Context;
use FormatD\KeyRunner\Security\Authentication\Provider\TOTPAuthenticationProvider;
use Neos\Flow\Security\AccountRepository;

abstract class DeliveryMethodFrontendController extends ActionController
{
    #[Flow\Inject]
    protected DeliveryMethodService $deliveryMethodService;

    #[Flow\Inject]
    protected TOTPService $TOTPService;

    #[Flow\Inject]
    protected Context $securityContext;

    #[Flow\Inject]
    protected AccountRepository $accountRepository;

    #[Flow\Inject]
    protected PartyRepository $partyRepository;

    protected string $successfullyAuthenticatedActionName = "successfullyAuthenticated";

    protected string $unsuccessfulAuthenticationActionName = "showInput";

    public function setupAction(string $providerName, AbstractParty $party)
    {
        $provider = $this->TOTPService->getProvider($providerName);
        if(!$provider) {
            throw new AuthenticationException(AuthenticationError::ProviderNotFound, 'The provider could not be found or is not a valid TOTP provider.');
        }

        $account = $this->createAccountForParty($providerName, $provider, $party);
        if (!$account) {
            throw new AuthenticationException(AuthenticationError::AccountCreationFailed, 'Failed to create an account for the specified party.');
        }
        $this->accountRepository->add($account);
        $party->addAccount($account);
        $this->partyRepository->update($party);

        $this->redirect("createdAccount", arguments: ["account" => $account]);
    }

    public function createdAccountAction(Account $account)
    {
        $this->view->assign("createdAccount", $account);
    }

    // FIXME: create DTO for $providerName and $id pair as they are forming some
	//        kind of "Context" and save them in the session instead of passing them around
    /**
     * Responsible for showing the Input field and errors if necessary
     * @param string $id
     * @param array<string,mixed> $errors
     * @return void
     */
    public function showInputAction(string $providerName, string $id, ?array $errors = null, ?string $redirectUri = null, ?string $redirectHash = null)
    {
        $this->view->assign("totp", $this->createTOTPDataForShowInput($providerName, $id));
        $this->view->assign("errors", $errors);
        $this->view->assign("hasErrors", !empty($errors));
		$this->view->assign("redirectUri", $redirectUri);
		$this->view->assign("redirectHash", $redirectHash);
    }

	protected function createTOTPDataForShowInput(string $providerName, string $id): array
	{
		return [
            "id" => $id,
            "providerName" => $providerName,
		];
	}

	public function verifyAction(string $providerName, string $id, ?string $redirectUri = null, ?string $redirectHash = null)
    {
        try {
            $this->verifyThatUserIsAuthenticatedByAccountWithId($providerName, $id);
            $this->redirect($this->successfullyAuthenticatedActionName, arguments: ["id" => $id, "providerName" => $providerName, "redirectUri" => $redirectUri, "redirectHash" => $redirectHash]);

        } catch (AuthenticationException $errors) {
			$this->handleFailedVerification(error: $errors, providerName: $providerName, id: $id, redirectUri: $redirectUri, redirectHash: $redirectHash);
        }
    }

	protected function handleFailedVerification(\Exception $error, string $providerName, string $id, ?string $redirectUri = null, ?string $redirectHash = null) {
		$errors = [
			"errorType" => $error->getCode(),
			"errorMessage" => $error->getMessage()
		];
		$this->redirect($this->unsuccessfulAuthenticationActionName, arguments: ["id" => $id, "providerName" => $providerName, "errors" => $errors, 'redirectUri' => $redirectUri, "redirectHash" => $redirectHash]);
	}

    abstract public function successfullyAuthenticatedAction(string $providerName, string $id, ?string $redirectUri = null, ?string $redirectHash = null);

    protected function createAccountForParty(string $providerName, TOTPAuthenticationProvider $provider, AbstractParty $party)
    {
        $deliveryMethod = $provider->getDeliveryMethod();
        $account = $this->TOTPService->createAccountForDeliveryMethod($providerName, $deliveryMethod);

        return $account;
    }

	protected function verifyThatUserIsAuthenticatedByAccountWithId(string $providerName, string $id)
	{
		$provider = $this->TOTPService->getProvider($providerName);

		if (!$provider) {
			throw new AuthenticationException(AuthenticationError::ProviderNotFound);
		}

		foreach ($this->securityContext->getAuthenticationTokens() as $token) {

			$account = $token->getAccount();
			if (!$account) {
				continue;
			}


			if ($account->getAuthenticationProviderName() !== $providerName) {
				continue;
			}

			if ($account->getAccountIdentifier() === $id) {
				return true;
			}
		}
		$this->addFlashMessage('Dieser Code ist nicht (mehr) gültig.', 'Ungültiger Code', \Neos\Error\Messages\Message::SEVERITY_ERROR);
		throw new AuthenticationException(AuthenticationError::InvalidOTP);
	}
}
