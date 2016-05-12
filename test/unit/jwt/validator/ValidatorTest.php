<?php

use JWX\JWT\Claim\Validator\EqualsValidator;


/**
 * @group jwt
 * @group validator
 */
class ValidatorTest extends PHPUnit_Framework_TestCase
{
	public function testInvoke() {
		$validator = new EqualsValidator();
		$this->assertTrue($validator(true, true));
	}
}
