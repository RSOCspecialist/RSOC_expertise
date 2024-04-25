import "hash"

rule evil_virus1{

meta:
	author = "ib_professional"
	description = "detecting malware that reads and backups passwords"
strings:
	$a1 = "/etc/passwd"
	$a2 = "/tmp/passwd.bak"
condition:
	$a1 and $a2 and hash.sha256(0, filesize) == "0aba95bafc985f6b2940b7d656210ff9606a1b39acc0cc5754fe0b32bd43cbf1"
}

rule evil_virus2{

meta:
	author = "ib_professional"
	description = "detecting malware that reads and backups passwords"
strings:
	$a1 = "/tmp/sh"
	$a2 = "/bin/sh"
condition:
	$a1 and $a2 and hash.sha256(0, filesize) == "1031201120414021302110311011302120212041102120213011102140111031201120214011101110511041201120212011203120112021401110111051102140111021103130212021101110511041201110214011103120113021101130511011"
}

