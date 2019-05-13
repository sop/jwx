<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\KeyAlgorithm\PBES2Algorithm;
use Sop\JWX\JWE\KeyAlgorithm\PBES2HS256A128KWAlgorithm;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWT\Parameter\PBES2CountParameter;
use Sop\JWX\JWT\Parameter\PBES2SaltInputParameter;

/**
 * @group jwe
 * @group key
 *
 * @internal
 */
class PBES2Test extends TestCase
{
    const PASSWORD = 'password';
    const SALT = 'salt';
    const COUNT = 256;

    public function testCreate()
    {
        $algo = new PBES2HS256A128KWAlgorithm(self::PASSWORD, self::SALT, self::COUNT);
        $this->assertInstanceOf(PBES2Algorithm::class, $algo);
        return $algo;
    }

    /**
     * @depends testCreate
     *
     * @param PBES2Algorithm $algo
     */
    public function testSaltInput(PBES2Algorithm $algo)
    {
        $this->assertEquals(self::SALT, $algo->saltInput());
    }

    /**
     * @depends testCreate
     *
     * @param PBES2Algorithm $algo
     */
    public function testSalt(PBES2Algorithm $algo)
    {
        $salt = $algo->salt();
        $this->assertIsString($salt);
    }

    /**
     * @depends testCreate
     *
     * @param PBES2Algorithm $algo
     */
    public function testIterationCount(PBES2Algorithm $algo)
    {
        $this->assertEquals(self::COUNT, $algo->iterationCount());
    }

    /**
     * @depends testCreate
     *
     * @param KeyManagementAlgorithm $algo
     */
    public function testHeaderParameters(KeyManagementAlgorithm $algo)
    {
        $params = $algo->headerParameters();
        $this->assertContainsOnlyInstancesOf(JWTParameter::class, $params);
    }

    public function testFromPassword()
    {
        $algo = PBES2HS256A128KWAlgorithm::fromPassword(self::PASSWORD);
        $this->assertInstanceOf(PBES2Algorithm::class, $algo);
    }

    public function testFromJWK()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::PASSWORD);
        $header = new Header(
            new AlgorithmParameter(JWA::ALGO_PBES2_HS256_A128KW),
            PBES2SaltInputParameter::fromString(self::SALT),
            new PBES2CountParameter(self::COUNT));
        $algo = PBES2Algorithm::fromJWK($jwk, $header);
        $this->assertInstanceOf(PBES2HS256A128KWAlgorithm::class, $algo);
    }

    public function testFromJWKMissingSalt()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::PASSWORD);
        $header = new Header(
            new AlgorithmParameter(JWA::ALGO_PBES2_HS256_A128KW),
            new PBES2CountParameter(self::COUNT));
        $this->expectException(\UnexpectedValueException::class);
        PBES2Algorithm::fromJWK($jwk, $header);
    }

    public function testFromJWKMissingCount()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::PASSWORD);
        $header = new Header(
            new AlgorithmParameter(JWA::ALGO_PBES2_HS256_A128KW),
            PBES2SaltInputParameter::fromString(self::SALT));
        $this->expectException(\UnexpectedValueException::class);
        PBES2Algorithm::fromJWK($jwk, $header);
    }

    public function testFromJWKInvalidAlgo()
    {
        $jwk = SymmetricKeyJWK::fromKey(self::PASSWORD);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_NONE),
            PBES2SaltInputParameter::fromString(self::SALT),
            new PBES2CountParameter(self::COUNT));
        $this->expectException(\UnexpectedValueException::class);
        PBES2Algorithm::fromJWK($jwk, $header);
    }
}
