<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\X509URLParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class X509URLParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new X509URLParameter('https://example.com/');
        $this->assertInstanceOf(X509URLParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_X509_URL, $param->name());
    }
}
