<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class JWKParameterTest extends TestCase
{
    public function testFromJSONValueBadCall()
    {
        $this->expectException(\BadMethodCallException::class);
        JWKParameter::fromJSONValue(null);
    }
}
