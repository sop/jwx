<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\AuthenticationTagParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class AuthenticationTagParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = AuthenticationTagParameter::fromString('abcdef');
        $this->assertInstanceOf(AuthenticationTagParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_AUTHENTICATION_TAG, $param->name());
    }

    public function testCreateFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        new AuthenticationTagParameter("\0");
    }
}
