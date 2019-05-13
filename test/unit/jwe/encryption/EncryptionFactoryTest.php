<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\ContentEncryptionAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\EncryptionAlgorithmFactory;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\EncryptionAlgorithmParameter;

/**
 * @group jwe
 * @group encryption
 *
 * @internal
 */
class EncryptionFactoryTest extends TestCase
{
    public function testAlgoByName()
    {
        $algo = EncryptionAlgorithmFactory::algoByName(JWA::ALGO_A128CBC_HS256);
        $this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
    }

    public function testAlgoByNameFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        EncryptionAlgorithmFactory::algoByName('nope');
    }

    public function testAlgoByHeader()
    {
        $header = new Header(new EncryptionAlgorithmParameter(JWA::ALGO_A128GCM));
        $algo = EncryptionAlgorithmFactory::algoByHeader($header);
        $this->assertInstanceOf(ContentEncryptionAlgorithm::class, $algo);
    }

    public function testAlgoByHeaderFail()
    {
        $this->expectException(\UnexpectedValueException::class);
        EncryptionAlgorithmFactory::algoByHeader(new Header());
    }
}
