<?php

use JWX\JWK\Parameter\JWKParameter;
use PHPUnit\Framework\TestCase;

/**
 * @group jwk
 * @group parameter
 */
class JWKParameterTest extends TestCase
{
    /**
     * @expectedException BadMethodCallException
     */
    public function testFromJSONValueBadCall()
    {
        JWKParameter::fromJSONValue(null);
    }
}
