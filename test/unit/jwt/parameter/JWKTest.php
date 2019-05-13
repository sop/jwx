<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWT\Parameter\JSONWebKeyParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class JSONWebKeyParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new JSONWebKeyParameter(new JWK());
        $this->assertInstanceOf(JSONWebKeyParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_JSON_WEB_KEY, $param->name());
    }

    /**
     * @depends testCreate
     *
     * @param JWTParameter $param
     */
    public function testFromJSONValue(JWTParameter $param)
    {
        $param = JSONWebKeyParameter::fromJSONValue($param->value());
        $this->assertInstanceOf(JSONWebKeyParameter::class, $param);
    }

    /**
     * @depends testCreate
     *
     * @param JSONWebKeyParameter $param
     */
    public function testJWK(JSONWebKeyParameter $param)
    {
        $jwk = $param->jwk();
        $this->assertInstanceOf(JWK::class, $jwk);
    }

    public function testFromJSONFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        JSONWebKeyParameter::fromJSONValue(null);
    }
}
