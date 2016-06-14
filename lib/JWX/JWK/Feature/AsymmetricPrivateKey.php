<?php

namespace JWX\JWK\Feature;

use CryptoUtil\PEM\PEM;


/**
 * Interface for JWK private keys of asymmetric key pair.
 */
interface AsymmetricPrivateKey
{
	/**
	 * Get the public key component of the asymmetric key pair.
	 *
	 * @return AsymmetricPublicKey
	 */
	public function publicKey();
	
	/**
	 * Convert private key to PEM.
	 *
	 * @return PEM
	 */
	public function toPEM();
}
