<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\PBES2SaltInputParameter;

/**
 * @group jwt
 * @group parameter
 *
 * @internal
 */
class PBES2SaltInputParameterTest extends TestCase
{
    public const SALT_INPUT = 'abcdef';

    public function testCreate()
    {
        $param = PBES2SaltInputParameter::fromString(self::SALT_INPUT);
        $this->assertInstanceOf(PBES2SaltInputParameter::class, $param);
        return $param;
    }

    /**
     * @depends testCreate
     */
    public function testParamName(JWTParameter $param)
    {
        $this->assertEquals(JWTParameter::PARAM_PBES2_SALT_INPUT, $param->name());
    }

    /**
     * @depends testCreate
     */
    public function testSaltInput(PBES2SaltInputParameter $param)
    {
        $this->assertEquals(self::SALT_INPUT, $param->saltInput());
    }
}
