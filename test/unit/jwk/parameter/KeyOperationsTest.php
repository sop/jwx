<?php

use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyOperationsParameter;

/**
 * @group jwk
 * @group parameter
 */
class KeyOperationsParameterTest extends PHPUnit_Framework_TestCase
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
     *
     * @param JWKParameter $param
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_KEY_OPERATIONS, $param->name());
    }
    
    /**
     * @depends testCreate
     *
     * @param JWKParameter $param
     */
    public function testFromJSONValue(JWKParameter $param)
    {
        $param = KeyOperationsParameter::fromJSONValue($param->value());
        $this->assertInstanceOf(KeyOperationsParameter::class, $param);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromJSONValueFail()
    {
        KeyOperationsParameter::fromJSONValue(null);
    }
}
