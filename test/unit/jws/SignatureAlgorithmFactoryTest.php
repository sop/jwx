<?php

use JWX\JWA\JWA;
use JWX\JWK\JWKSet;
use JWX\JWK\Parameter\KeyIDParameter as JWKID;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWS\SignatureAlgorithm;
use JWX\JWS\Algorithm\SignatureAlgorithmFactory;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\KeyIDParameter as JWTID;

/**
 * @group jws
 */
class SignatureAlgorithmFactoryTest extends PHPUnit_Framework_TestCase
{
    public function testAlgoByKey()
    {
        $jwk = SymmetricKeyJWK::fromKey("test");
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256));
        $factory = new SignatureAlgorithmFactory($header);
        $algo = $factory->algoByKey($jwk);
        $this->assertInstanceOf(SignatureAlgorithm::class, $algo);
    }
    
    public function testAlgoByKeys()
    {
        $jwk = SymmetricKeyJWK::fromKey("test")->withParameters(new JWKID("id"));
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256),
            new JWTID("id"));
        $factory = new SignatureAlgorithmFactory($header);
        $algo = $factory->algoByKeys(new JWKSet($jwk));
        $this->assertInstanceOf(SignatureAlgorithm::class, $algo);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testAlgoByKeysNoHeaderID()
    {
        $jwk = SymmetricKeyJWK::fromKey("test")->withParameters(new JWKID("id"));
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256));
        $factory = new SignatureAlgorithmFactory($header);
        $factory->algoByKeys(new JWKSet($jwk));
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testAlgoByKeysNoKeyID()
    {
        $jwk = SymmetricKeyJWK::fromKey("test");
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256),
            new JWTID("id"));
        $factory = new SignatureAlgorithmFactory($header);
        $factory->algoByKeys(new JWKSet($jwk));
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testUnsupportedAlgoFail()
    {
        $jwk = SymmetricKeyJWK::fromKey("test");
        $header = new Header(new AlgorithmParameter(JWA::ALGO_A128KW));
        $factory = new SignatureAlgorithmFactory($header);
        $factory->algoByKey($jwk);
    }
}
