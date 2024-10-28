import "hash"
import "pe"

rule Intellpui{

meta:
	author = "ib_professional"
	description = "trojan malware Intellpui"
condition:
	pe.imphash() == "1e64e6af59a4d296028fd4dbdbeb790c" or hash.sha256(0, filesize) == "d649055cc890b139e00eabe0b207df147fa2ec630c17fb2575047b2593b288f5"
}


