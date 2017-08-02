<?php

use JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 */
class JWKParameterTest extends PHPUnit_Framework_TestCase
{
    /**
     * @expectedException BadMethodCallException
     */
    public function testFromJSONValueBadCall()
    {
        JWKParameter::fromJSONValue(null);
    }
}
