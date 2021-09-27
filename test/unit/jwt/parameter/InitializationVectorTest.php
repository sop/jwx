<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\InitializationVectorParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class InitializationVectorParameterTest extends TestCase
{
    public const IV = 'abcdef';

    public function testCreate()
    {
        $param = InitializationVectorParameter::fromString(self::IV);
        $this->assertInstanceOf(InitializationVectorParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_INITIALIZATION_VECTOR,
            $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testIV(InitializationVectorParameter $param)
    {
        $this->assertEquals(self::IV, $param->initializationVector());
    }
}
