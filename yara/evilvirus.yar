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
	$a1 and $a2 and hash.sha256(0, filesize) == "7960581d154297567c2c07c1e5073fa67d1d2ebaea1450766d34aa1951751672"
}

