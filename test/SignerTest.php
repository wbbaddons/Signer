<?php
namespace wcf\util {
	class PasswordUtil {
		public static function secureCompare($a, $b) {
			$a = (string) $a;
			$b = (string) $b;
			
			return $a === $b;
		}
	}
}

namespace {
	require_once __DIR__.'/../file/util/Signer.class.php';
	require_once 'PHPUnit/Framework/TestCase.php';
	use \wcf\util\Signer;
	
	/**
	 * Testcase for signer
	 * 
	 * @author 	Tim Düsterhus
	 * @copyright	2013 Tim Düsterhus
	 * @license	BSD 3-Clause License <http://opensource.org/licenses/BSD-3-Clause>
	 * @package	be.bastelstu.wcf.signer
	 */
	class SignerTest extends PHPUnit_Framework_TestCase {
		public static function setUpBeforeClass() {
			define('SIGNER_SECRET', 'secret');
		}
		
		/**
		 * Tests Signer::getSignature()
		 */
		public function testGetSignature() {
			$this->assertEquals('cd33db5a64e8a2185659da6f09dc78676bc5a19a', Signer::getSignature('a'));
			$this->assertEquals('f72bf6ad61628dec3c2bc6b9530f63c51244e77b', Signer::getSignature('b'));
			
		}
		
		/**
		 * Tests Signer::createSignedString()
		 */
		public function testCreateSignedString() {
			$this->assertEquals('cd33db5a64e8a2185659da6f09dc78676bc5a19a-YQ==', Signer::createSignedString('a'));
			$this->assertEquals('f72bf6ad61628dec3c2bc6b9530f63c51244e77b-Yg==', Signer::createSignedString('b'));
		}
		
		/**
		 * Tests Signer::validateSignedString()
		 */
		public function testValidateSignedString() {
			$this->assertTrue(Signer::validateSignedString('cd33db5a64e8a2185659da6f09dc78676bc5a19a-YQ=='));
			$this->assertTrue(Signer::validateSignedString('f72bf6ad61628dec3c2bc6b9530f63c51244e77b-Yg=='));
			
			$this->assertTrue(Signer::validateSignedString(Signer::createSignedString('a')));
			$this->assertTrue(Signer::validateSignedString(Signer::createSignedString('b')));
			
			$this->assertFalse(Signer::validateSignedString('f72bf6ad61628dec3c2bc6b9530f63c51244e77b-Xg=='));
			$this->assertFalse(Signer::validateSignedString('f72bf6ad61628dec3c2bc6b9530f63c51244e77c-Yg=='));
			
			$this->assertFalse(Signer::validateSignedString(null));
			$this->assertFalse(Signer::validateSignedString(false));
			$this->assertFalse(Signer::validateSignedString(1));
			$this->assertFalse(Signer::validateSignedString('x'));
			$this->assertFalse(Signer::validateSignedString(''));
			$this->assertFalse(Signer::validateSignedString('-'));
			$this->assertFalse(Signer::validateSignedString('x-y'));
			$this->assertFalse(Signer::validateSignedString('-y'));
			$this->assertFalse(Signer::validateSignedString('x-'));
		}
		
		/**
		 * Tests Signer::getValueFromSignedString()
		 */
		public function testGetValueFromSignedString() {
			$this->assertEquals('a', Signer::getValueFromSignedString('cd33db5a64e8a2185659da6f09dc78676bc5a19a-YQ=='));
			$this->assertEquals('b', Signer::getValueFromSignedString('f72bf6ad61628dec3c2bc6b9530f63c51244e77b-Yg=='));
			
			$this->assertEquals('a', Signer::getValueFromSignedString(Signer::createSignedString('a')));
			$this->assertEquals('b', Signer::getValueFromSignedString(Signer::createSignedString('b')));
			
			$this->assertNull(Signer::getValueFromSignedString('cd33db5a64e8a2185659da6f09dc78676bc5a19a-XQ=='));
			$this->assertNull(Signer::getValueFromSignedString('f72bf6ad61628dec3c2bc6b9530f63c51244e77c-Yg=='));
			
			$this->assertNull(Signer::getValueFromSignedString(null));
			$this->assertNull(Signer::getValueFromSignedString(false));
			$this->assertNull(Signer::getValueFromSignedString(1));
			$this->assertNull(Signer::getValueFromSignedString('x'));
			$this->assertNull(Signer::getValueFromSignedString(''));
			$this->assertNull(Signer::getValueFromSignedString('-'));
			$this->assertNull(Signer::getValueFromSignedString('x-y'));
			$this->assertNull(Signer::getValueFromSignedString('-y'));
			$this->assertNull(Signer::getValueFromSignedString('x-'));
		}
	}
}
