<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\KeyOperationsParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class KeyOperationsParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new KeyOperationsParameter(KeyOperationsParameter::OP_SIGN,
            KeyOperationsParameter::OP_VERIFY);
        $this->assertInstanceOf(KeyOperationsParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_KEY_OPERATIONS, $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testFromJSONValue(JWKParameter $param)
    {
        $param = KeyOperationsParameter::fromJSONValue($param->value());
        $this->assertInstanceOf(KeyOperationsParameter::class, $param);
    }

    public function testFromJSONValueFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        KeyOperationsParameter::fromJSONValue(null);
    }

    /**
     * @depends testCreate
     */
    public function testFromNameAndValue(JWKParameter $param)
    {
        $p = JWKParameter::fromNameAndValue($param->name(), $param->value());
        $this->assertEquals($p, $param);
    }
}
