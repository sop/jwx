<?php

use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\AlgorithmParameter as JWKAlgo;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter as JWTAlgo;

/**
 * @group jwa
 */
class JWATest extends PHPUnit_Framework_TestCase
{
    public function testDeriveByHeader()
    {
        $header = new Header(new JWTAlgo(JWA::ALGO_NONE));
        $alg = JWA::deriveAlgorithmName($header);
        $this->assertEquals(JWA::ALGO_NONE, $alg);
    }
    
    public function testDeriveByJWK()
    {
        $header = new Header();
        $jwk = new JWK(new JWKAlgo(JWA::ALGO_NONE));
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        $this->assertEquals(JWA::ALGO_NONE, $alg);
    }
    
    public function testDeriveByHeaderAndJWK()
    {
        $header = new Header(new JWTAlgo(JWA::ALGO_NONE));
        $jwk = new JWK(new JWKAlgo(JWA::ALGO_NONE));
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        $this->assertEquals(JWA::ALGO_NONE, $alg);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testDeriveByHeaderAndJWKMismatch()
    {
        $header = new Header(new JWTAlgo(JWA::ALGO_NONE));
        $jwk = new JWK(new JWKAlgo(JWA::ALGO_A128KW));
        JWA::deriveAlgorithmName($header, $jwk);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testDeriveNoAlgoFail()
    {
        $header = new Header();
        $jwk = new JWK();
        JWA::deriveAlgorithmName($header, $jwk);
    }
}
