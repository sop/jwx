<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWKSetURLParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class JWKSetURLParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new JWKSetURLParameter('https://example.com/');
        $this->assertInstanceOf(JWKSetURLParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_JWK_SET_URL, $param->name());
    }
}
