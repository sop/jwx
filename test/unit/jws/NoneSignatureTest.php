<?php

use JWX\JWA\JWA;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWS\Algorithm\NoneAlgorithm;
use JWX\JWT\Parameter\AlgorithmParameterValue;

/**
 * @group jws
 */
class NoneSignatureTest extends PHPUnit_Framework_TestCase
{
    const DATA = "CONTENT";
    
    public function testCreate()
    {
        $algo = new NoneAlgorithm();
        $this->assertInstanceOf(SignatureAlgorithm::class, $algo);
        return $algo;
    }
    
    /**
     * @depends testCreate
     *
     * @param AlgorithmParameterValue $algo
     */
    public function testAlgoParamValue(AlgorithmParameterValue $algo)
    {
        $this->assertEquals(JWA::ALGO_NONE, $algo->algorithmParamValue());
    }
    
    /**
     * @depends testCreate
     *
     * @param SignatureAlgorithm $algo
     */
    public function testSign(SignatureAlgorithm $algo)
    {
        $sig = $algo->computeSignature(self::DATA);
        $this->assertEquals("", $sig);
        return $sig;
    }
    
    /**
     * @depends testCreate
     * @depends testSign
     *
     * @param SignatureAlgorithm $algo
     * @param string $signature
     */
    public function testValidate(SignatureAlgorithm $algo, $signature)
    {
        $this->assertTrue($algo->validateSignature(self::DATA, $signature));
    }
}
