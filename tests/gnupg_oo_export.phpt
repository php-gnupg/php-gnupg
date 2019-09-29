--TEST--
export a key
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = new gnupg();
$gpg->seterrormode(gnupg::ERROR_WARNING);
$ret = $gpg->export($fingerprint);
var_dump($ret);
?>
--EXPECTF--
string(%d) "-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF11JawBCAC6bWTtKtAj1dBih/UHR9iH1iADEmZde52aKyd7EXKtjs4Q2aXJ
kbn9R+kcJNx+AlnTSePQBkNz5brmEAQgk93rOsHaPUEROkfBR2C6AkjaJNnk0E43
pbUy6bWhmGR4kmpbvRnR/7kxVyplb5zSFAcio1I8RQ3ql0HkF//zLUouYzrMJn6e
GvffHw1revlSxo0leCcOsNE7AHGVgMxvUWYO0JT4Fs+JcpsTxG8MFE6I6SLZoY5W
XmtOsO0vMNJoTaXdqfJoLTkviPkRUZuF0DtzuT1oQLUTTaKvWxx2+33YF5HYrlNy
eepLFLh5mZ1/2HFWoQo2X1gFfb1R9EJPbFtJABEBAAG0GVBIUCBHbnVQRyA8Z251
cGdAcGhwLm5ldD6JATgEEwECACIFAl11JawCGwMGCwkIBwMCBhUIAgkKCwQWAgMB
Ah4BAheAAAoJEGaed14KYoSzo2QH/AxR9nAqevgbp2GHw+xw4R8XVHMeL2atROFU
ndldeYmtVNGh8ck/YSxMz/FY2qLbN3421xOi/ct7nVl77MLZxgZAnsD5qnm0doJl
Su/URzUmyhinKLmB9AdklGJNXrL0/dWF0t46Dmv+4W+Qnx3mNhZBUbSW5Ut2pXq0
d4XPTHfkQWgaTPblw97ncQzwVmDSLRqoJEl3yo3OW8/uE1a/ldivuMux5IEcA03l
5L/5g2QOe9cRxk+x9JCXBPqjJ9OIVMUUReGBVSfscGAhnD0bW/aNf5//eGkU9Gai
CCSdnIKCopRJSIZcv3OF+P+vh3gmGXAByyQKRvwpBdvosIsiEXi5AQ0EXXUlrAEI
AO43Q3D/VgdGGpHa4P0ppv6gY5jBnPHvpyd3Opu497H0z6Xe8rZfRxSpyOViPjF4
NIe2OX6tEAK/hYkH0o91BwbMGAwiljKomL45G4vPb0ve86d/MGrtdeDRt8WhlDEB
VfKpxi1bFtq7KvHvnv51iATndM1wE2v79vssMdmJEPRipo+GHiPoThEoO2bdtwI1
thHpUsdXPGpeMcM3F9FmdYpdsFsoyzZ6if7cbijhO4OArGNUm3oJTu66Vok9GjSa
V7HsLHJMNf/6Lc66FQSG8+kUKZ/R7s8NY+fS2oFONba3DT5qzA80rfiAFheeAFUz
HE3NLkkdPsnzNBOOtRot3bUAEQEAAYkBHwQYAQIACQUCXXUlrAIbDAAKCRBmnnde
CmKEs3t+B/4vUc2oXZXuEzIfL7Atv20VJomQCHrsbnNHErqCDJ+TpH6yjcKGGBNR
zlOOUpZWFN1Ii2Wml+XIIzOXiOhhH/A6iTTAVl72RQWwiRjm8kYYWThT4msPd5yX
QulbZRMxorIIrzs0tjIc5z5FXhSQhIaRjMSKqwJ/VGS9KEWut1F5akJNv/3klMW6
UTIxnj0IMlnL+GaPBf+f1+3Pxoli37aeISxzvLhtquLXc++ls9ICwF6CN9D+Vtp+
H2JaNPDtdHUzVBv0xQ1E3B1XeCiOIDFwWPWvCCY1FbgKXNrn5fdgsk69dLtTGJ4A
WU7na8AWygvMcdtuGjpNE4g24ln7Rrce
=sQ2w
-----END PGP PUBLIC KEY BLOCK-----
"
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>