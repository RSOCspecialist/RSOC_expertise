import "hash"
import "pe"

rule hellerror{

meta:
	author = "ib_professional"
	description = "trojan malware hellerror"
condition:
	hash.sha256(0, filesize) == "2c6c0edc953907d4f65049544433b4b48cb6fc23e29d3f327cd975fb05ca2b9b"
}


