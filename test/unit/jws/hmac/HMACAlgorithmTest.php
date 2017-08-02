<?php

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\AlgorithmParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWK\Parameter\KeyValueParameter;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWS\Algorithm\HMACAlgorithm;
use JWX\JWT\Header\Header;

/**
 * @group jws
 * @group hmac
 */
class HMACAlgorithmTest extends PHPUnit_Framework_TestCase
{
    public function testFromJWK()
    {
        $jwk = new JWK(new AlgorithmParameter(JWA::ALGO_HS256),
            new KeyTypeParameter(KeyTypeParameter::TYPE_OCT),
            new KeyValueParameter("key"));
        $algo = HMACAlgorithm::fromJWK($jwk, new Header());
        $this->assertInstanceOf(HMACAlgorithm::class, $algo);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testFromJWKUnsupportedAlgo()
    {
        $jwk = SymmetricKeyJWK::fromKey("key")->withParameters(
            new AlgorithmParameter("nope"));
        HMACAlgorithm::fromJWK($jwk, new Header());
    }
    
    /**
     * @expectedException RuntimeException
     */
    public function testComputeFails()
    {
        $algo = new HMACAlgorithmTest_InvalidAlgo("key");
        $algo->computeSignature("data");
    }
}

class HMACAlgorithmTest_InvalidAlgo extends HMACAlgorithm
{
    protected function _hashAlgo()
    {
        return "nope";
    }
    
    public function algorithmParamValue()
    {
        return $this->_hashAlgo();
    }
}
