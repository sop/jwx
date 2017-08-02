<?php

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWE\KeyAlgorithm\KeyAlgorithmFactory;
use JWX\JWK\JWKSet;
use JWX\JWK\Parameter\KeyIDParameter as JWKID;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;
use JWX\JWT\Parameter\KeyIDParameter;

/**
 * @group jwe
 * @group key
 */
class KeyAlgorithmFactoryTest extends PHPUnit_Framework_TestCase
{
    const KEY_ID = "test-key";
    
    private static $_header;
    
    public static function setUpBeforeClass()
    {
        self::$_header = new Header(new AlgorithmParameter(JWA::ALGO_DIR),
            new KeyIDParameter(self::KEY_ID));
    }
    
    public static function tearDownAfterClass()
    {
        self::$_header = null;
    }
    
    public function testAlgoByKey()
    {
        $jwk = SymmetricKeyJWK::fromKey("test");
        $factory = new KeyAlgorithmFactory(self::$_header);
        $algo = $factory->algoByKey($jwk);
        $this->assertInstanceOf(KeyManagementAlgorithm::class, $algo);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testAlgoByKeyUnsupportedFail()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_HS256));
        $jwk = SymmetricKeyJWK::fromKey("test");
        $factory = new KeyAlgorithmFactory($header);
        $factory->algoByKey($jwk);
    }
    
    public function testAlgoByKeys()
    {
        $jwk = SymmetricKeyJWK::fromKey("test", new JWKID(self::KEY_ID));
        $factory = new KeyAlgorithmFactory(self::$_header);
        $algo = $factory->algoByKeys(new JWKSet($jwk));
        $this->assertInstanceOf(KeyManagementAlgorithm::class, $algo);
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testAlgoByKeysNoKeyIDParam()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR));
        $jwk = SymmetricKeyJWK::fromKey("test", new JWKID(self::KEY_ID));
        $factory = new KeyAlgorithmFactory($header);
        $factory->algoByKeys(new JWKSet($jwk));
    }
    
    /**
     * @expectedException UnexpectedValueException
     */
    public function testAlgoByKeysNoKey()
    {
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR),
            new KeyIDParameter("fail"));
        $jwk = SymmetricKeyJWK::fromKey("test", new JWKID(self::KEY_ID));
        $factory = new KeyAlgorithmFactory($header);
        $factory->algoByKeys(new JWKSet($jwk));
    }
}
