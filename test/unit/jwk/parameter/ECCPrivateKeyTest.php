<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\Parameter\ECCPrivateKeyParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;

/**
 * @group jwk
 * @group parameter
 *
 * @internal
 */
class ECCPrivateKeyParameterTest extends TestCase
{
    public function testCreate()
    {
        $param = ECCPrivateKeyParameter::fromString('0123456789abcdef');
        $this->assertInstanceOf(ECCPrivateKeyParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWKParameter $param)
    {
        $this->assertEquals(JWKParameter::PARAM_ECC_PRIVATE_KEY, $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testPrivateKeyOctets(ECCPrivateKeyParameter $param)
    {
        $this->assertEquals('0123456789abcdef', $param->privateKeyOctets());
    }
}
