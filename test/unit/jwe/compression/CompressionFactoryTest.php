<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\CompressionAlgorithm;
use Sop\JWX\JWE\CompressionAlgorithm\CompressionFactory;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\CompressionAlgorithmParameter;

/**
 * @group jwe
 * @group compression
 *
 * @internal
 */
class CompressionFactoryTest extends TestCase
{
    public function testAlgoByName()
    {
        $algo = CompressionFactory::algoByName(JWA::ALGO_DEFLATE);
        $this->assertInstanceOf(CompressionAlgorithm::class, $algo);
    }

    public function testUnsupportedAlgo()
    {
        $this->expectException(\UnexpectedValueException::class);
        CompressionFactory::algoByName('nope');
    }

    public function testAlgoByHeader()
    {
        $header = new Header(
            new CompressionAlgorithmParameter(JWA::ALGO_DEFLATE));
        $algo = CompressionFactory::algoByHeader($header);
        $this->assertInstanceOf(CompressionAlgorithm::class, $algo);
    }

    public function testAlogByHeaderMissingParam()
    {
        $this->expectException(\UnexpectedValueException::class);
        CompressionFactory::algoByHeader(new Header());
    }
}
