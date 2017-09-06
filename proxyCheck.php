<?php
/**
 * @version 1.0
 * @package SNB proxy
 * @copyright &copy; 2008 security-net.biz
 * @author Ivan Markovic <ivanm@security-net.biz>
 */
 
/**
 * Proxy check functions.
 * Collection of some functions that can help proxy detection
 * Contains common methods needed as:
 * headers check, open ports check, cookie trap.
 * 
 * Sample usage:
 * $myProxy = new proxyCheck();
 * $myProxy->serverVar = $_SERVER;
 * $headers = $myProxy->checkHeder();
 * $ports = $myProxy->checkPort();
 */

class proxyCheck {
	  
	  /**
	   * Server vars ($_SERVER)
	   * @access public
	   * @var array
	   */
	  var $serverVar = array();
	  
	   /**
	   * Timeout for fsockopen
	   * @access public
	   * @var int
	   */
	  var $timeout = 5;
	  
	  /**
	   * Common ports for testing
	   * @access public
	   * @var array
	   */
	  var $ports = array(3128,8080,80);
	  
	  /**
	   * Cookie name
	   * @access public
	   * @var string
	   */
	  var $cookieName = "proxyCheck";
	  
	  /**
	   * Finded headers
	   * @access private
	   * @var array
	   */
	  private $proxyHeder = array();
	  
	  /**
	   * Finded open ports
	   * @access private
	   * @var array
	   */
	  private $portsData = array();
	  
	  /**
	   * URL of proxy URL check
	   * @access public
	   * @var string
	   */
	  var $proxyUrl = '';
	  
	  
	  /**
		 * proxyCheck constructor
		 * @access public
		 */
		function proxyCheck() {
			// TODO
		}
	
		/**
		 * Check usual proxy headers
		 * @return array data
		 * @access public
		 */
		function checkHeder() {
			
			  if(isset($this->serverVar['HTTP_X_FORWARDED_FOR'])) {
			  		$this->proxyHeder['HTTP_X_FORWARDED_FOR'] = $this->serverVar['HTTP_X_FORWARDED_FOR'];
			  }
			  
	  	  if(isset($this->serverVar['HTTP_X_FORWARDED'])) {
	  			  $this->proxyHeder['HTTP_X_FORWARDED'] = $this->serverVar['HTTP_X_FORWARDED'];
			  }
			  
			  if(isset($this->serverVar['HTTP_FORWARDED'])) {
	  			  $this->proxyHeder['HTTP_FORWARDED'] = $this->serverVar['HTTP_FORWARDED'];
			  }
			  
			  if(isset($this->serverVar['HTTP_PROXY_AGENT'])) {
	  			  $this->proxyHeder['HTTP_PROXY_AGENT'] = $this->serverVar['HTTP_PROXY_AGENT'];
			  }
			  
			  if(isset($this->serverVar['HTTP_VIA'])) {
	  			  $this->proxyHeder['HTTP_VIA'] = $this->serverVar['HTTP_VIA'];
			  }
			  
			  if(isset($this->serverVar['HTTP_PROXY_CONNECTION'])) {
	  			  $this->proxyHeder['HTTP_PROXY_CONNECTION'] = $this->serverVar['HTTP_PROXY_CONNECTION'];
			  }
			  
			  if(isset($this->serverVar['HTTP_CLIENT_IP'])) {
	  			  $this->proxyHeder['HTTP_CLIENT_IP'] = $this->serverVar['HTTP_CLIENT_IP'];
			  }
			  
			  return $this->proxyHeder;
		}
		
		/**
		 * Check common ports
		 * @param string ip
		 * @return array data
		 * @access public
		 */
		function checkPort($ip = '') {
			
			  if(empty($ip)) $ip = $this->serverVar['REMOTE_ADDR'];
			
				foreach($this->ports as $port) {
						$fp = @fsockopen($ip,$port,$errno,$errstr,$this->timeout);
						if(!empty($fp)) $this->portsData[$port] == $port;
						@fclose($fp);
				}
				
				return $this->portsData;
		}
		
		/**
		 * Cookie trap
		 * @return true on finded proxy
		 * @access public
		 */
		function checkCookie() {
				if(isset($_COOKIE[$this->cookieName])) {
						if($this->serverVar['REMOTE_ADDR'] != $_COOKIE[$this->cookieName]) return true;
				} else {
						@setcookie($this->cookieName, $this->serverVar['REMOTE_ADDR']);	
				}
		}
		
		
		
		/**
		 * Connect back using CURL
		 * @return data from proxyUrl
		 * @access public
		 */
		function connectBack() {
		    if(!empty($this->proxyUrl)) {
		    	  $buffer = array();
					  foreach($this->ports as $key => $val) {
									$curl_handle = curl_init();
		    				  curl_setopt($curl_handle, CURLOPT_URL, $this->proxyUrl);
		    				  curl_setopt($curl_handle, CURLOPT_PROXY, $this->serverVar['REMOTE_ADDR'].":".$val);  
		    				  curl_setopt($curl_handle, CURLOPT_USERAGENT, $this->serverVar['HTTP_USER_AGENT']);  
		    				  curl_setopt($curl_handle, CURLOPT_RETURNTRANSFER, 1);
		    				  curl_setopt($curl_handle, CURLOPT_HEADER, 0);
		    				  $buffer[$val] = curl_exec($curl_handle);
		    				  curl_close($curl_handle);
		    				  return $buffer;
						}
			 } else return 'Empty proxyUrl.';
		}
		
}

?>
