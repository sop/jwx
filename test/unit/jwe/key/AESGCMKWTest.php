<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\A128GCMKWAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\AESGCMKWAlgorithm;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\InitializationVectorParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class AESGCMKWTest extends TestCase
{
    public const KEY_128 = '123456789 123456';

    public const IV = '123456789 12';

    public function testHeaderParams()
    {
        $algo = new A128GCMKWAlgorithm(self::KEY_128, self::IV);
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }

    public function testInvalidIVFail()
    {
        $this->expectException(\LengthException::class);
        new A128GCMKWAlgorithm(self::KEY_128, 'fail');
    }

    public function testDecryptMissingAuthTag()
    {
        $algo = new A128GCMKWAlgorithm(self::KEY_128, self::IV);
        $this->expectException(\RuntimeException::class);
        $algo->decrypt('');
    }

    public function testFromJWK()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_A128GCMKW),
            InitializationVectorParameter::fromString(self::IV));
        $algo = AESGCMKWAlgorithm::fromJWK($jwk, $header);
        $this->assertInstanceOf(A128GCMKWAlgorithm::class, $algo);
    }

    public function testFromJWKNoAlgo()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
        $header = new Header(InitializationVectorParameter::fromString(self::IV));
        $this->expectException(\UnexpectedValueException::class);
        AESGCMKWAlgorithm::fromJWK($jwk, $header);
    }

    public function testFromJWKNoIV()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_A128GCMKW));
        $this->expectException(\UnexpectedValueException::class);
        AESGCMKWAlgorithm::fromJWK($jwk, $header);
    }

    public function testFromJWKUnsupportedAlgo()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::KEY_128);
        $header = new Header(InitializationVectorParameter::fromString(self::IV),
            new AlgorithmParameter(JWA::ALGO_NONE));
        $this->expectException(\UnexpectedValueException::class);
        AESGCMKWAlgorithm::fromJWK($jwk, $header);
    }

    public function testFromKey()
    {
        $algo = A128GCMKWAlgorithm::fromKey(self::KEY_128);
        $this->assertInstanceOf(A128GCMKWAlgorithm::class, $algo);
    }
}
