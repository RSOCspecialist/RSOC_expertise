import "hash"
import "pe"

rule AFXML{

meta:
	author = "ib_professional"
	description = "trojan malware AFXML"
condition:
	pe.imphash() == "bd62874739b904e4a5a0cac4b1c54b67" or hash.sha256(0, filesize) == "e2735841dd8ae66a825182d6d06629821c49aca44357e5980c3bfb97ace7ebf0"
}


