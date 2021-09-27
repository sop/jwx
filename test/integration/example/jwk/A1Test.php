<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWK\Parameter\AlgorithmParameter;
use Sop\JWX\JWK\Parameter\CurveParameter;
use Sop\JWX\JWK\Parameter\ExponentParameter;
use Sop\JWX\JWK\Parameter\JWKParameter;
use Sop\JWX\JWK\Parameter\KeyTypeParameter;
use Sop\JWX\JWK\Parameter\ModulusParameter;
use Sop\JWX\JWK\Parameter\PublicKeyUseParameter;
use Sop\JWX\JWK\Parameter\XCoordinateParameter;
use Sop\JWX\JWK\Parameter\YCoordinateParameter;

/**
 * Test case for RFC 7517 appendix A.1.
 * Example Public Keys.
 *
 * @group example
 *
 * @see https://tools.ietf.org/html/rfc7517#appendix-A.1
 *
 * @internal
 */
class JWKPublicKeysTest extends TestCase
{
    /**
     * @return JWKSet
     */
    public function testJWKSet()
    {
        $jwkset = JWKSet::fromJSON(
            file_get_contents(TEST_ASSETS_DIR . '/example/rfc7517-a1-jwk.json'));
        $this->assertInstanceOf(JWKSet::class, $jwkset);
        return $jwkset;
    }

    /**
     * @depends testJWKSet
     */
    public function testKeyCount(JWKSet $jwkset)
    {
        $this->assertCount(2, $jwkset);
    }

    /**
     * @depends testJWKSet
     *
     * @return JWK
     */
    public function testKey1(JWKSet $jwkset)
    {
        $jwk = $jwkset->keyByID('1');
        $this->assertInstanceOf(JWK::class, $jwk);
        return $jwk;
    }

    /**
     * @depends testJWKSet
     *
     * @return JWK
     */
    public function testKey2(JWKSet $jwkset)
    {
        $jwk = $jwkset->keyByID('2011-04-29');
        $this->assertInstanceOf(JWK::class, $jwk);
        return $jwk;
    }

    /**
     * @depends testKey1
     *
     * @return KeyTypeParameter
     */
    public function testKey1Type(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_KEY_TYPE);
        $this->assertInstanceOf(KeyTypeParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey1Type
     */
    public function testKey1TypeValue(KeyTypeParameter $param)
    {
        $this->assertEquals('EC', $param->value());
    }

    /**
     * @depends testKey1
     *
     * @return CurveParameter
     */
    public function testKey1Curve(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_CURVE);
        $this->assertInstanceOf(CurveParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey1Curve
     */
    public function testKey1CurveParam(CurveParameter $param)
    {
        $this->assertEquals(CurveParameter::CURVE_P256, $param->value());
    }

    /**
     * @depends testKey1
     *
     * @return XCoordinateParameter
     */
    public function testKey1XCoord(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_X_COORDINATE);
        $this->assertInstanceOf(XCoordinateParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey1XCoord
     */
    public function testKey1XCoordValue(XCoordinateParameter $param)
    {
        $this->assertEquals('MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
            $param->value());
    }

    /**
     * @depends testKey1
     *
     * @return YCoordinateParameter
     */
    public function testKey1YCoord(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_Y_COORDINATE);
        $this->assertInstanceOf(YCoordinateParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey1YCoord
     */
    public function testKey1YCoordValue(YCoordinateParameter $param)
    {
        $this->assertEquals('4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
            $param->value());
    }

    /**
     * @depends testKey1
     *
     * @return PublicKeyUseParameter
     */
    public function testKey1Use(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_PUBLIC_KEY_USE);
        $this->assertInstanceOf(PublicKeyUseParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey1Use
     */
    public function testKey1UseValue(PublicKeyUseParameter $param)
    {
        $this->assertEquals('enc', $param->value());
    }

    /**
     * @depends testKey2
     *
     * @return KeyTypeParameter
     */
    public function testKey2Type(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_KEY_TYPE);
        $this->assertInstanceOf(KeyTypeParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey2Type
     */
    public function testKey2TypeValue(KeyTypeParameter $param)
    {
        $this->assertEquals('RSA', $param->value());
    }

    /**
     * @depends testKey2
     *
     * @return ModulusParameter
     */
    public function testKey2Modulus(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_MODULUS);
        $this->assertInstanceOf(ModulusParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey2Modulus
     */
    public function testKey2ModulusValue(ModulusParameter $param)
    {
        $num = $param->number();
        $this->assertEquals(256, strlen($num->base256()));
    }

    /**
     * @depends testKey2
     *
     * @return ExponentParameter
     */
    public function testKey2Exponent(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_EXPONENT);
        $this->assertInstanceOf(ExponentParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey2Exponent
     */
    public function testKey2ExponentValue(ExponentParameter $param)
    {
        $this->assertEquals(65537, $param->number()->base10());
    }

    /**
     * @depends testKey2
     *
     * @return AlgorithmParameter
     */
    public function testKey2Algo(JWK $jwk)
    {
        $param = $jwk->get(JWKParameter::PARAM_ALGORITHM);
        $this->assertInstanceOf(AlgorithmParameter::class, $param);
        return $param;
    }

    /**
     * @depends testKey2Algo
     */
    public function testKey2AlgoValue(AlgorithmParameter $param)
    {
        $this->assertEquals('RS256', $param->value());
    }
}
