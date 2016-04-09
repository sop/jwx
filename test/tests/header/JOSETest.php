<?php

use JWX\Header\JOSE;
use JWX\Header\Header;
use JWX\Header\Parameter\TypeParameter;
use JWX\Header\Parameter\ContentTypeParameter;
use JWX\Header\Parameter\RegisteredParameter;


/**
 * @group header
 */
class JOSETest extends PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$header = new Header(new TypeParameter("test"));
		$jose = new JOSE($header);
		$this->assertTrue($jose->has(RegisteredParameter::NAME_TYPE));
	}
	
	public function testMerge() {
		$h1 = new Header(new TypeParameter("test"));
		$h2 = new Header(new ContentTypeParameter("test"));
		$jose = new JOSE($h1, $h2);
		$this->assertCount(2, $jose);
	}
	
	/**
	 * @expectedException RuntimeException
	 */
	public function testDuplicateFail() {
		$h1 = new Header(new TypeParameter("test1"));
		$h2 = new Header(new TypeParameter("test2"));
		$jose = new JOSE($h1, $h2);
	}
}
