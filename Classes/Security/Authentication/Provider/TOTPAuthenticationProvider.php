<?php
declare(strict_types=1);
namespace FormatD\KeyRunner\Security\Authentication\Provider;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Core\Bootstrap;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use FormatD\KeyRunner\Security\Authentication\Token\OtpToken;
use FormatD\KeyRunner\Service\TOTPService;
use FormatD\KeyRunner\Service\DeliveryMethodService;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;
use GVB\Website\Domain\Repository\UserRepository;


class TOTPAuthenticationProvider extends AbstractProvider
{
    #[Flow\Inject]
    protected DeliveryMethodService $deliveryMethodService;

    #[Flow\Inject]
    protected SecurityContext $securityContext;

    #[Flow\Inject]
    protected AccountFactory $accountFactory;

    #[Flow\Inject]
    protected AccountRepository $accountRepository;

    public function getTokenClassNames(): array
    {
        return [OTPToken::class];
    }

    /**
     * @param TokenInterface $authenticationToken
     * @throws AuthenticationRequiredException | UnsupportedAuthenticationTokenException
     */
    public function authenticate(TokenInterface $authenticationToken): void
    {
        if (!$authenticationToken instanceof OTPToken) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1549978976);
        }

        $otp = $authenticationToken->getOtp();
        $id = $authenticationToken->getId();

        $deliveryMethod = $this->getDeliveryMethod();

        $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($id, $this->name);
        if (!$account) {
            // Create dummy data to be verified to be resilient against Timing-Attacks
            $otp = "123456789012b";
            $account = $this->accountFactory->createAccountWithPassword("1234", "12345");
        }

        if ($deliveryMethod->verify($otp, $account)) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
        } else {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
        }
    }

    public function getDeliveryMethod()
    {
        $name = trim($this->options["tokenDeliveryMethod"] ?? "");
        $deliveryMethod = $this->deliveryMethodService->getDeliveryMethod($name);
        if (!$deliveryMethod) {
            throw new \Exception("Unknown DeliveryMethod configured '$name'");
        }
        return $deliveryMethod;
    }
}
