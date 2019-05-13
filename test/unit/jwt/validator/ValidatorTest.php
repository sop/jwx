<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Claim\Validator\EqualsValidator;

/**
 * @group jwt
 * @group validator
 *
 * @internal
 */
class ValidatorTest extends TestCase
{
    public function testInvoke()
    {
        $validator = new EqualsValidator();
        $this->assertTrue($validator(true, true));
    }
}
