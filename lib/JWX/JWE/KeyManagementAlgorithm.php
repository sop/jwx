<?php

namespace JWX\JWE;

use JWX\JWT\Header\Header;
use JWX\JWT\Header\HeaderParameters;
use JWX\JWT\Parameter\AlgorithmParameterValue;


/**
 * Base class for algorithms used for CEK management for the content encryption
 * algorithms.
 */
abstract class KeyManagementAlgorithm implements AlgorithmParameterValue, 
	HeaderParameters
{
	/**
	 * Encrypt a key.
	 *
	 * @param string $key Key to be encrypted
	 * @param Header $header Reference to the Header variable, that shall
	 *        be updated to contain parameters specific to the encryption
	 * @return string Ciphertext
	 */
	abstract protected function _encryptKey($key, Header &$header);
	
	/**
	 * Decrypt a key.
	 *
	 * @param string $ciphertext Ciphertext of the encrypted key
	 * @param Header $header Header possibly containing encoding specific
	 *        parameters
	 * @return string Plaintext key
	 */
	abstract protected function _decryptKey($ciphertext, Header $header);
	
	/**
	 * Encrypt a key to be inserted into JWE header.
	 *
	 * @param string $cek Content encryption key
	 * @param Header|null $header Optional reference to the Header variable,
	 *        which may be updated to contain parameters specific to this
	 *        encrypt invocation. If the variable is referenced, but is a null,
	 *        it shall be initialized to an empty Header.
	 * @throws \RuntimeException For generic errors
	 * @return string Encrypted key
	 */
	final public function encrypt($cek, Header &$header = null) {
		if (!isset($header)) {
			$header = new Header();
		}
		return $this->_encryptKey($cek, $header);
	}
	
	/**
	 * Decrypt a CEK from the encrypted data.
	 *
	 * @param string $data Encrypted key
	 * @param Header|null Optional header containing parameters required to
	 *        decrypt the key.
	 * @throws \RuntimeException For generic errors
	 * @return string Content encryption key
	 */
	final public function decrypt($data, Header $header = null) {
		if (!isset($header)) {
			$header = new Header();
		}
		return $this->_decryptKey($data, $header);
	}
	
	/**
	 * Get content encryption key for the encryption.
	 *
	 * Returned key may be random depending on the key management algorithm.
	 *
	 * @param int $length Required key size in bytes
	 * @return string
	 */
	abstract public function cekForEncryption($length);
}
