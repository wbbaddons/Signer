<?php
namespace wcf\system\exception {
	class SystemException extends \Exception {}
}

namespace {
	require_once __DIR__.'/../file/lib/util/Signer.class.php';
	require_once 'PHPUnit/Framework/TestCase.php';
	use \wcf\util\Signer;
	
	/**
	 * Testcase for hmac
	 * 
	 * @author 	Maximilian Mader
	 * @copyright	2013 Tim Düsterhus
	 * @license	BSD 3-Clause License <http://opensource.org/licenses/BSD-3-Clause>
	 * @package	be.bastelstu.wcf.signer
	 */
	class HMACTest extends PHPUnit_Framework_TestCase {
		public $method;

		public function setUp() {
			$this->method = new ReflectionMethod(
				'\wcf\util\Signer', 'hmac'
			);
			
			$this->method->setAccessible(true);
		}
		
		/**
		 * Tests with test data from RFC 2104
		 * @see http://tools.ietf.org/html/rfc2104#page-8
		 *
		 * @covers \wcf\util\Signer::hmac
		 */
		public function testRFCTestData() {
			$this->assertSame('9294727a3638bb1c13f48ef8158bfc9d', $this->method->invokeArgs(null, array('md5', 'Hi There', str_repeat("\x0B", 16))));
			$this->assertSame('750c783e6ab0b503eaa86e310a5db738', $this->method->invokeArgs(null, array('md5', 'what do ya want for nothing?', 'Jefe')));
			$this->assertSame('56be34521d144c88dbb8c733f0e8b3f6', $this->method->invokeArgs(null, array('md5', str_repeat("\xDD", 50), str_repeat("\xAA", 16))));
		}
		
		/**
		 * Tests with test data from RCF 2104 againt hash_hmac
		 * @see http://tools.ietf.org/html/rfc2104#page-8
		 *
		 * @covers \wcf\util\Signer::hmac
		 */
		public function testRFCTestDataCompare() {
			$data = 'Hi There';
			$key = str_repeat("\x0B", 16);
			
			$this->assertSame(hash_hmac('md5', $data, $key), $this->method->invokeArgs(null, array('md5', $data, $key)));
			$this->assertSame(hash_hmac('sha1', $data, $key), $this->method->invokeArgs(null, array('sha1', $data, $key)));
			$this->assertSame(hash_hmac('md5', $data, $key, true), $this->method->invokeArgs(null, array('md5', $data, $key, true)));
			$this->assertSame(hash_hmac('sha1', $data, $key, true), $this->method->invokeArgs(null, array('sha1', $data, $key, true)));
			
			$data = 'what do ya want for nothing?';
			$key = 'Jefe';
			
			$this->assertSame(hash_hmac('md5', $data, $key), $this->method->invokeArgs(null, array('md5', $data, $key)));
			$this->assertSame(hash_hmac('sha1', $data, $key), $this->method->invokeArgs(null, array('sha1', $data, $key)));
			$this->assertSame(hash_hmac('md5', $data, $key, true), $this->method->invokeArgs(null, array('md5', $data, $key, true)));
			$this->assertSame(hash_hmac('sha1', $data, $key, true), $this->method->invokeArgs(null, array('sha1', $data, $key, true)));
			
			$data = str_repeat("\x0D", 50);
			$key = str_repeat("\x0A", 16);
			
			$this->assertSame(hash_hmac('md5', $data, $key), $this->method->invokeArgs(null, array('md5', $data, $key)));
			$this->assertSame(hash_hmac('sha1', $data, $key), $this->method->invokeArgs(null, array('sha1', $data, $key)));
			$this->assertSame(hash_hmac('md5', $data, $key, true), $this->method->invokeArgs(null, array('md5', $data, $key, true)));
			$this->assertSame(hash_hmac('sha1', $data, $key, true), $this->method->invokeArgs(null, array('sha1', $data, $key, true)));
		}
		
		/**
		 * Tests with random data againt hash_hmac
		 *
		 * @covers \wcf\util\Signer::hmac
		 */
		public function testRandomData() {
			for ($i = 0; $i < 10; $i++) {
				$key = sha1($i . (microtime() * $i));
				$data = $i.md5($i.$i);
				
				$this->assertSame(hash_hmac('md5', $data, $key), $this->method->invokeArgs(null, array('md5', $data, $key)));
				$this->assertSame(hash_hmac('sha1', $data, $key), $this->method->invokeArgs(null, array('sha1', $data, $key)));
				$this->assertSame(hash_hmac('md5', $data, $key, true), $this->method->invokeArgs(null, array('md5', $data, $key, true)));
				$this->assertSame(hash_hmac('sha1', $data, $key, true), $this->method->invokeArgs(null, array('sha1', $data, $key, true)));
			}
		}
		
		/**
		 * Tests with random data againt hash_hmac
		 *
		 * @covers \wcf\util\Signer::hmac
		 */
		public function testRandomBinaryData() {
			for ($i = 0; $i < 10; $i++) {
				$key = sha1($i . (microtime() * $i));
				$data = pack('C*', $i.md5($i.$i));
				
				$this->assertSame(hash_hmac('md5', $data, $key), $this->method->invokeArgs(null, array('md5', $data, $key)));
				$this->assertSame(hash_hmac('sha1', $data, $key), $this->method->invokeArgs(null, array('sha1', $data, $key)));
				$this->assertSame(hash_hmac('md5', $data, $key, true), $this->method->invokeArgs(null, array('md5', $data, $key, true)));
				$this->assertSame(hash_hmac('sha1', $data, $key, true), $this->method->invokeArgs(null, array('sha1', $data, $key, true)));
			}
		}
		
		/**
		 * Tests key greater than block size
		 *
		 * @covers \wcf\util\Signer::hmac
		 */
		public function testTooLongKey() {
			$key = 'Never gonna give you up, never gonna let you down, never gonna run around and desert you ...';
			$data = 'The Game';
			
			$this->assertSame(hash_hmac('md5', $data, $key), $this->method->invokeArgs(null, array('md5', $data, $key)));
			$this->assertSame(hash_hmac('sha1', $data, $key), $this->method->invokeArgs(null, array('sha1', $data, $key)));
			$this->assertSame(hash_hmac('md5', $data, $key, true), $this->method->invokeArgs(null, array('md5', $data, $key, true)));
			$this->assertSame(hash_hmac('sha1', $data, $key, true), $this->method->invokeArgs(null, array('sha1', $data, $key, true)));
		}
		
		
		
		/**
		 * @expectedException wcf\system\exception\SystemException
		 *
		 * @covers \wcf\util\Signer::hmac
		 */
		public function testInvalidAlgorithm() {
			$this->method->invokeArgs(null, array('totallyInvalidHashingAlgorithm', 'some data', 'some key'));
		}
	}
}
