<?php

namespace JWX\JWT\Parameter;


interface AlgorithmParameterValue
{
	/**
	 * Get algorithm type as an 'alg' parameter value
	 *
	 * @return string
	 */
	public function algorithmParamValue();
}
