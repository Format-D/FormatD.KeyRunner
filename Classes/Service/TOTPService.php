<?php
namespace FormatD\KeyRunner\Service;

use FormatD\KeyRunner\Security\Authentication\Token\OTPToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Context;
use FormatD\KeyRunner\Domain\TokenHandler;
use FormatD\KeyRunner\Security\Authentication\Provider\TOTPAuthenticationProvider;
use Neos\Flow\Utility\Algorithms;
use Neos\Flow\Security\Authentication\TokenAndProviderFactoryInterface;
use Neos\Party\Domain\Model\AbstractParty;

#[Flow\Scope("singleton")]
class TOTPService
{

    /**
     * @var array<TOTPAuthenticationProvider>
     */
    protected array $providers = [];

    #[Flow\Inject]
    protected TokenAndProviderFactoryInterface $tokenAndProviderFactory;

	#[Flow\Inject]
    protected Context $securityContext;

    public function isTwoFactorAuthenticationEnabledFor(Account $account): bool
    {
        foreach ($this->getProviders() as $name => $provider) {
            if ($name === $account->getAuthenticationProviderName()) {
                return true;
            }
        }

        return false;
    }

    public function createAccountForDeliveryMethod(string $providerName, TokenHandler $deliveryMethod): ?Account
    {
        $identifier = Algorithms::generateUUID();
        $secret = $deliveryMethod->createSecretForNewAccount();

        $account = new Account();
        $account->setAccountIdentifier($identifier);
        $account->setCredentialsSource($secret);
        $account->setAuthenticationProviderName($providerName);

        return $account;
    }

    public function hasUserTwoFactorAccount(?AbstractParty $party): Account|false
    {
		if($party !== null) {
			foreach($party->getAccounts() as $account) {
				if($this->getProvider($account->getAuthenticationProviderName())) {
					return $account;
				}
			}
		}
        return false;
    }

	public function isUserTwoFactorAuthenticated(): bool 
	{
		$tokens = $this->securityContext->getAuthenticationTokensOfType(OTPToken::class);
		foreach($tokens as $token) {
			if ($this->getProvider($token->getAuthenticationProviderName()) === null) {
				continue;
			}
			if ($token->isAuthenticated()) {
				return true;
			}
		}
		return false;
	}

    /**
     * @return array<TOTPAuthenticationProvider>
     */
    public function getProviders(): array
    {
        if (!$this->providers) {
            $this->providers = array_filter($this->tokenAndProviderFactory->getProviders(), fn($p) => $p instanceof TOTPAuthenticationProvider);
        }
        return $this->providers;
    }

    public function getProvider(string $name): ?TOTPAuthenticationProvider
    {
        return $this->getProviders()[$name] ?? null;
    }
}
