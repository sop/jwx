<?php

namespace JWX\JWK\Feature;

use CryptoUtil\PEM\PEM;


/**
 * Interface for JWK public keys of asymmetric key pair.
 */
interface AsymmetricPublicKey
{
	/**
	 * Convert public key to PEM.
	 *
	 * @return PEM
	 */
	public function toPEM();
}
