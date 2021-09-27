<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\Parameter\AlgorithmParameter;
use Sop\JWX\JWK\Parameter\KeyTypeParameter;
use Sop\JWX\JWK\Parameter\KeyValueParameter;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\Algorithm\HMACAlgorithm;
use Sop\JWX\JWT\Header\Header;

/**
 * @group jws
 * @group hmac
 *
 * @internal
 */
class HMACAlgorithmTest extends TestCase
{
    public function testFromJWK()
    {
        $jwk = new JWK(new AlgorithmParameter(JWA::ALGO_HS256),
            new KeyTypeParameter(KeyTypeParameter::TYPE_OCT),
            new KeyValueParameter('key'));
        $algo = HMACAlgorithm::fromJWK($jwk, new Header());
        $this->assertInstanceOf(HMACAlgorithm::class, $algo);
    }

    public function testFromJWKUnsupportedAlgo()
    {
        $jwk = SymmetricKeyJWK::fromKey('key')->withParameters(
            new AlgorithmParameter('nope'));
        $this->expectException(\UnexpectedValueException::class);
        HMACAlgorithm::fromJWK($jwk, new Header());
    }

    /**
     * @requires PHP < 8
     */
    public function testComputeFails()
    {
        $algo = new HMACAlgorithmTest_InvalidAlgo('key');
        $this->expectException(\RuntimeException::class);
        $algo->computeSignature('data');
    }

    /**
     * @requires PHP >= 8
     */
    public function testComputeFailsPhp8()
    {
        $algo = new HMACAlgorithmTest_InvalidAlgo('key');
        $this->expectException(\ValueError::class);
        $algo->computeSignature('data');
    }
}

class HMACAlgorithmTest_InvalidAlgo extends HMACAlgorithm
{
    public function algorithmParamValue(): string
    {
        return $this->_hashAlgo();
    }

    protected function _hashAlgo(): string
    {
        return 'nope';
    }
}
