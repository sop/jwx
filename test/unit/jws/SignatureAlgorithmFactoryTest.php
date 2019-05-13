<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWK\JWKSet;
use Sop\JWX\JWK\Parameter\KeyIDParameter as JWKID;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWS\Algorithm\SignatureAlgorithmFactory;
use Sop\JWX\JWS\SignatureAlgorithm;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\KeyIDParameter as JWTID;

/**
 * @group jws
 *
 * @internal
 */
class SignatureAlgorithmFactoryTest extends TestCase
{
    public function testAlgoByKey()
    {
        $jwk = SymmetricKeyJWK::fromKey('test');
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256));
        $factory = new SignatureAlgorithmFactory($header);
        $algo = $factory->algoByKey($jwk);
        $this->assertInstanceOf(SignatureAlgorithm::class, $algo);
    }

    public function testAlgoByKeys()
    {
        $jwk = SymmetricKeyJWK::fromKey('test')->withParameters(new JWKID('id'));
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256),
            new JWTID('id'));
        $factory = new SignatureAlgorithmFactory($header);
        $algo = $factory->algoByKeys(new JWKSet($jwk));
        $this->assertInstanceOf(SignatureAlgorithm::class, $algo);
    }

    public function testAlgoByKeysNoHeaderID()
    {
        $jwk = SymmetricKeyJWK::fromKey('test')->withParameters(new JWKID('id'));
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256));
        $factory = new SignatureAlgorithmFactory($header);
        $this->expectException(\UnexpectedValueException::class);
        $factory->algoByKeys(new JWKSet($jwk));
    }

    public function testAlgoByKeysNoKeyID()
    {
        $jwk = SymmetricKeyJWK::fromKey('test');
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256),
            new JWTID('id'));
        $factory = new SignatureAlgorithmFactory($header);
        $this->expectException(\UnexpectedValueException::class);
        $factory->algoByKeys(new JWKSet($jwk));
    }

    public function testUnsupportedAlgoFail()
    {
        $jwk = SymmetricKeyJWK::fromKey('test');
        $header = new Header(new AlgorithmParameter(JWA::ALGO_A128KW));
        $factory = new SignatureAlgorithmFactory($header);
        $this->expectException(\UnexpectedValueException::class);
        $factory->algoByKey($jwk);
    }
}
