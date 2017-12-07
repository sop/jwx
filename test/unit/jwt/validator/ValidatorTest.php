<?php

use JWX\JWT\Claim\Validator\EqualsValidator;
use PHPUnit\Framework\TestCase;

/**
 * @group jwt
 * @group validator
 */
class ValidatorTest extends TestCase
{
    public function testInvoke()
    {
        $validator = new EqualsValidator();
        $this->assertTrue($validator(true, true));
    }
}
