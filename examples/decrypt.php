<?php
require_once	(dirname(__FILE__)."/main.php");

$mailtext	=	'
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1.2.5 (GNU/Linux)

hQIOA8VdBLDv7dV1EAgAtEMlQ1K/iXYIgPLiojfEhaTOvyEhDjZZ/9Gr5IQ/UvXZ
nQW0KYuIpYB8Oe7SC/n3NDqcLuS9Q8GMBgcQjLQKIjEtu0I2xcXATjpNEooKgSqp
KxWtoobsPNkCrVyK1dEH911vr/sGcjpiX5L0dYMldq5So45979AaUirpX4pmu7ay
1YB81iciq3/KmR+ocOMWzT+v6WJFB0rXSoFc1WiwSiw6TcotXdZA9hAllwaRuBMQ
2Vct7/F+dTqZRD4mBt8WiksJFvPm8bb+5p4QVt9eVkuxJv8w7mROVEDFYsDeh8GG
FxEzYBr1yv+9DG3Hkmtqk6Ns6VZH4roB9RdwKU2XlggAq/6DiqYnuV9+xuKYvF1G
+8X/MWOg2Di6xqe8GqujGmq3ztFb5wNDc+Rp4aW9YgbHHLf9VFc21QAEozjfTe6S
hQbcY02UrkJ8bQ4LigWtNnvM3XzQw/J+LQFYij/QogvO3inNVMFd+/WEoJNZ7EMB
sE68F32hPsumPhpheyfD19SX2Nejrlaqa4qYCuhNUR0luI4Xti6ymX3jAXJsozNa
zP/Ho1T/fCwohyJYaOe7S+u99fcVrchmGP77qiPNQUMsY1LthY1LMihq+0Kd+ORM
Hc7HHGvV8/ufIB9WFWNOhQW+gOfIfGzQidLaw+AI7ar68FciKwce9aX99yffVx3U
y9JHAWS6GctPfUHl1ZiS/1hq5s7xcWHsh7KTPwv449OsXIWFitnDH6jCL1sqQPjq
3pNJXapRMRsyKi60i8jV+KIDl0O0Q9S6eEY=
=Rb4q
-----END PGP MESSAGE-----

';
$gnupg		->	addDecryptKey		($fingerprint,$passphrase);
$plaintext	=	$gnupg	->	decrypt	($mailtext);

echo "\n".$plaintext."\n";
?>
