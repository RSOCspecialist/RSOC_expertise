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
	$a1 and $a2 and hash.rle(0, filesize) == "0113021102140412031201130111031202120214011202120311011204110113021102120411011101150114021102120211021302110212041101110115011204110112011303120212011101150114021101120411011302110312011103150111"
}

