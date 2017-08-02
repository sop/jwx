<?php

namespace JWX\JWE\KeyAlgorithm;

use JWX\JWA\JWA;
use JWX\JWE\KeyManagementAlgorithm;
use JWX\JWE\KeyAlgorithm\Feature\RandomCEK;
use JWX\JWK\JWK;
use JWX\JWK\Symmetric\SymmetricKeyJWK;
use JWX\JWT\Header\Header;
use JWX\JWT\Parameter\AlgorithmParameter;

/**
 * Base class for algorithms implementing AES key wrap.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-4.4
 */
abstract class AESKWAlgorithm extends KeyManagementAlgorithm
{
    use RandomCEK;
    
    /**
     * Key encryption key.
     *
     * @var string $_kek
     */
    protected $_kek;
    
    /**
     * Key wrapping algorithm.
     *
     * Lazily initialized.
     *
     * @var \AESKW\AESKeyWrapAlgorithm|null $_kw
     */
    protected $_kw;
    
    /**
     * Mapping from algorithm name to class name.
     *
     * @internal
     *
     * @var array
     */
    const MAP_ALGO_TO_CLASS = array(
        /* @formatter:off */
        JWA::ALGO_A128KW => A128KWAlgorithm::class, 
        JWA::ALGO_A192KW => A192KWAlgorithm::class, 
        JWA::ALGO_A256KW => A256KWAlgorithm::class
        /* @formatter:on */
    );
    
    /**
     * Get the size of the key encryption key in bytes.
     *
     * @return int
     */
    abstract protected function _kekSize();
    
    /**
     * Get key wrapping algorithm instance.
     *
     * @return \AESKW\AESKeyWrapAlgorithm
     */
    abstract protected function _AESKWAlgo();
    
    /**
     * Constructor.
     *
     * @param string $kek Key encryption key
     */
    public function __construct($kek)
    {
        if (strlen($kek) != $this->_kekSize()) {
            throw new \LengthException(
                "Key encryption key must be " . $this->_kekSize() . " bytes.");
        }
        $this->_kek = $kek;
    }
    
    /**
     *
     * @param JWK $jwk
     * @param Header $header
     * @throws \UnexpectedValueException
     * @return AESKWAlgorithm
     */
    public static function fromJWK(JWK $jwk, Header $header)
    {
        $jwk = SymmetricKeyJWK::fromJWK($jwk);
        $alg = JWA::deriveAlgorithmName($header, $jwk);
        if (!array_key_exists($alg, self::MAP_ALGO_TO_CLASS)) {
            throw new \UnexpectedValueException("Unsupported algorithm '$alg'.");
        }
        $cls = self::MAP_ALGO_TO_CLASS[$alg];
        return new $cls($jwk->key());
    }
    
    /**
     * Get key wrapping algorithm.
     *
     * @return \AESKW\AESKeyWrapAlgorithm
     */
    protected function _kw()
    {
        if (!isset($this->_kw)) {
            $this->_kw = $this->_AESKWAlgo();
        }
        return $this->_kw;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _encryptKey($key, Header &$header)
    {
        return $this->_kw()->wrap($key, $this->_kek);
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _decryptKey($ciphertext, Header $header)
    {
        return $this->_kw()->unwrap($ciphertext, $this->_kek);
    }
    
    /**
     *
     * @see \JWX\JWE\KeyManagementAlgorithm::headerParameters()
     * @return \JWX\JWT\Parameter\JWTParameter[]
     */
    public function headerParameters()
    {
        return array_merge(parent::headerParameters(),
            array(AlgorithmParameter::fromAlgorithm($this)));
    }
}
