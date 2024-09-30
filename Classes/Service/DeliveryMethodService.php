<?php
namespace FormatD\KeyRunner\Service;

use Neos\Flow\Annotations as Flow;
use FormatD\KeyRunner\Domain\TokenHandler;

#[Flow\Scope("singleton")]
class DeliveryMethodService
{
    #[Flow\InjectConfiguration(path: "deliveryMethods")]
    protected array $deliveryMethodsConfiguration;

    /**
     * @var array<string, TokenHandler>
     */
    protected array $deliveryMethods;

    public function initializeObject()
    {
        foreach ($this->deliveryMethodsConfiguration as $name => $configuration) {
            try {
                $this->deliveryMethods[$name] = TokenHandler::fromConfiguration($name, $configuration);
            } catch (\Throwable $th) {
                // stub
            }
        }
    }

    public function getDeliveryMethod(string $name): ?TokenHandler
    {
        return $this->deliveryMethods[$name] ?? null;
    }
}
