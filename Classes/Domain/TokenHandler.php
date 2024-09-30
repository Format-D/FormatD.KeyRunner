<?php

namespace FormatD\KeyRunner\Domain;

use OTPHP\TOTP;
use Neos\Flow\Security\Account;
use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
class TokenHandler
{
    protected function __construct(
        public readonly string $name,
        public readonly string $frontendController,
        public readonly array $options
    ) {

    }

    public function verify(string $otpInput, Account $account): bool
    {
        $totp = $this->createTOTP(withSettingsFromAccount: $account);
        return $totp->verify($otpInput);
    }

    public function createSecretForNewAccount(): string
    {
        return $this->createSecret();
    }

    public function generateCurrentOneTimePasswordForAccount(Account $account): ?string
    {
        return $this->createTOTP(withSettingsFromAccount: $account)->now();
    }

    protected function createSecret(): string
    {
        return $this->createTOTP()->getSecret();
    }

    protected function createTOTP(?Account $withSettingsFromAccount = null)
	{
        return TOTP::create(
            secret: $withSettingsFromAccount?->getCredentialsSource(),
            period: $this->options["period"] ?? 30,
            digits: $this->options["digits"] ?? 6
        );
    }

    static function fromConfiguration(string $name, array $configuration): self
    {
        return new self(
            $name,
            $configuration["frontendController"],
            $configuration["options"] ?? [],
        );
    }
}
