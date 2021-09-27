<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\KeyValueParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class KeyValueParameterTest extends TestCase
{
    public const KEY = 'password';

    public function testCreate()
    {
        $param = KeyValueParameter::fromString(self::KEY);
        $this->assertInstanceOf(KeyValueParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_KEY_VALUE, $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testKey(KeyValueParameter $param)
    {
        $this->assertEquals(self::KEY, $param->key());
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
