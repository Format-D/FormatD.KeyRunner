# FormatD.KeyRunner

FormatD KeyRunner is a Neos package that implements two-factor authentication (2FA) based on TOTP (Time-Based One-Time Password). This package enhances the security of your Neos CMS by allowing the use of time-based one-time passwords.

#### Features

- Two-Factor Authentication (2FA): Enables TOTP-based two-factor authentication for user accounts, adding an extra layer of security.
- TOTP Support: Compatible with standard TOTP generators (e.g., Google Authenticator, Authy).
- Token Management: Provides a flexible and secure token handling service, including the creation and validation of tokens.

#### Usage

##### Enabling Two-Factor Authentication (2FA)

To enable two-factor authentication for a user, call the TOTPService methods. Below is an example:

```php
use FormatD\KeyRunner\Service\TOTPService;

class SomeController extends ActionController
{
    #[Flow\Inject]
    protected TOTPService $totpService;

    public function enableTwoFactorAction(Account $account): void
    {
        $isEnabled = $this->totpService->isTwoFactorAuthenticationEnabledFor($account);
        if (!$isEnabled) {
            // Logic to enable 2FA
        }
    }
}
```

##### Creating a TOTP Account

To create a new account for 2FA, use the following method from the TOTPService:

```php
$account = $this->totpService->createAccountForDeliveryMethod('TOTPProvider', $deliveryMethod);
```

##### Authenticating Users

Use the isUserTwoFactorAuthenticated() method to check if a user has successfully completed 2FA during the login process:

```php
$isAuthenticated = $this->totpService->isUserTwoFactorAuthenticated();
if ($isAuthenticated) {
    // Proceed with authenticated actions
}
```

##### Custom Delivery Methods

FormatD KeyRunner provides flexibility in how the one-time passwords (OTPs) are delivered to users. You can implement custom delivery methods such as email, SMS, or any other communication channel.

The core idea is that a DeliveryMethodService is responsible for handling how the OTPs are sent to the user. For instance, you can implement custom logic to send the OTP via email or SMS based on the user’s preferences.

tbd ...