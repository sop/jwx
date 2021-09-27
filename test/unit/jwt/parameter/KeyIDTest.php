<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\KeyIDParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class JWTKeyIDParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = new KeyIDParameter('');
        $this->assertInstanceOf(KeyIDParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_KEY_ID, $param->name());
    }
}
