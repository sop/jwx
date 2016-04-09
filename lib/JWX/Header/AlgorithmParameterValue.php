<?php

namespace JWX\Header;


interface AlgorithmParameterValue
{
	/**
	 * Get algorithm type as an 'alg' parameter value
	 *
	 * @return string
	 */
	public function algorithmParamValue();
}
