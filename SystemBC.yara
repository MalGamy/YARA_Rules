rule SystemBC_malware: SystemBC 
{
    meta:
	description = "Detect_SystemBC"
	author = "@malgamy12"
	date = "2023/1/9"
        license = "DRL 1.1"
        hash = "b369ed704c293b76452ee1bdd99a69bbb76b393a4a9d404e0b5df59a00cff074"
        hash = "0da6157c9b27d5a07ce34f32f899074dd5b06891d5323fbe28d5d34733bbdaf8"
        hash = "70874b6adc30641b33ed83f6321b84d0aef1cf11de2cb78f78c9d3a45c5221c0"
        hash = "bf1f17dce8eccc400641a0824da39cea19c2dd0c9833855542abb189bd0e5f7e"
        hash = "3c10661e4d448ee95acf71b03a31e12181956a72cd2d75934b583c4e19321be8"
        hash = "fe2512e3e965a50f35a332cfc310069697ad797e782c32ba30596b4c88f9e090"
        hash = "2072b666365701aed7143e9d241ab975e21af78fce6bbf14fd0bdd6c137a18ce"
        hash = "0e5a3f858456145f09d44201ceed7bef5a96451875f2327ac7c3e8cbdeb7a856"
        hash = "252270954f4544d236b6ff7cb9b9151262f8369c1f9a256c647bcb02277ab7ef"
        hash = "2a4bd69263a466d5c81cc76efba740cbb90440628eb58c10203d7a9aa8fbee59"
        hash = "0bacbe9942287d0273c7b2cf7125cb01c85964ad67012205a0f8eb31b382c511"
        hash = "018de46acf37d72323c17393a105e3aeae8751e53dba2bd056d4d432a6de98e2"
        hash = "a6ab4d3120570214d762ccc1222a4a1559ef6e46cee214ec375974025dcec997"
        hash = "c23d52a06ec6552de165f9261628dff15fd03b07c8dd2247aa2968a05ee1a90e"
        hash = "47cbe4c03441a7796c8d3a2bdaeb998969d5137dd0469db891318606cff1f432"
        hash = "4c9a783544c7f44fb3f058837f0d5723fdaabbeb22b58ce635667b3ba2c6e7d3"
        hash = "21adaf466ea988688d3e107a0f95237817189bce0b4f05d232f9d30b97bf68d4"
    strings:
	$s1 = "GET /tor/rendezvous2/%s HTTP" ascii
        $s2 = "https://api.ipify.org/"
        $s3 = "https://ip4.seeip.org/"
        $s4 = "directory-footer"
        $s5 = "KEY-----"
        $op1 = {8A 94 2B [4] 02 C2 8A 8C 28 [4] 88 8C 2B [4] 88 94 28 [4] 02 CA 8A 8C 29 [4] 30 0E 48 FF C6 48 FF CF}
    condition:
        uint16(0) == 0x5A4D and all of them
}
