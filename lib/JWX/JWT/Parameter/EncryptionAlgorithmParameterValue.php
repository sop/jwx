<?php

namespace JWX\JWT\Parameter;


interface EncryptionAlgorithmParameterValue
{
	/**
	 * Get algorithm type as an 'enc' parameter value
	 *
	 * @return string
	 */
	public function encryptionAlgorithmParamValue();
}
