<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\JWK;
use Sop\JWX\JWK\Parameter\AlgorithmParameter as JWKAlgo;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter as JWTAlgo;

/**
 * @group jwa
 *
 * @internal
 */
class JWATest extends TestCase
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

    public function testDeriveByHeaderAndJWKMismatch()
    {
        $header = new Header(new JWTAlgo(JWA::ALGO_NONE));
        $jwk = new JWK(new JWKAlgo(JWA::ALGO_A128KW));
        $this->expectException(\UnexpectedValueException::class);
        JWA::deriveAlgorithmName($header, $jwk);
    }

    public function testDeriveNoAlgoFail()
    {
        $header = new Header();
        $jwk = new JWK();
        $this->expectException(\UnexpectedValueException::class);
        JWA::deriveAlgorithmName($header, $jwk);
    }
}
