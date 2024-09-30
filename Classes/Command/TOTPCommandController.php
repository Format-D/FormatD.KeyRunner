<?php
namespace FormatD\KeyRunner\Command;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;
use OTPHP\TOTP;

/**
 * @Flow\Scope("singleton")
 */
class TOTPCommandController extends CommandController
{
	public function testCommand()
	{
		$totp = TOTP::create();
		$this->outputLine($totp->getSecret());
	}
	public function generateCommand()
	{
		$secret = '5ZOCOLTTEZZX2LBWMBS7XVRQCDPAPSXBACM3EARU3F67JFB7J7OP7CLZKA2FWAJMGBHAOPJUYG76PZPQLMRBZT3BWE3IQZ4GVGTMCIA';
		$totp = TOTP::create($secret);
		$this->outputLine($totp->now());
	}
}

