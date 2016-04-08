<?php

namespace JWX\JWS\Algorithm;


class RS256Algorithm extends RSAPKCS1Algorithm
{
	protected function _mdMethod() {
		return "sha256WithRSAEncryption";
	}
	
	public function algorithmParamValue() {
		return "RS256";
	}
}
