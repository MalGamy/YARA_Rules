rule APT_APT32_MAL_Bot_Nov22 : APT32 
{
	meta:
	    description = "Detects unknown bot malware used by APT32"
	    author = "@malgamy12"
        date = "2022-11-06"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
	    hash1 = "93054d3abc36019ccfe88f87363363e6ca9b77f4"
        hash2 = "0eadbd6ef9f5930257530ac5a3b8abb49c9755d1"
        hash3 = "69c2d292179dc615bfe4d7f880b5f9928604558e"
        hash4 = "616306489de4029da7271eadbdf090cee22ae1af"
        hash5 = "ecb8edfddd812a125b515dc42a2e93569c1caed9"
        hash6 = "a86f3faf1eedb7325023616adf37a62c9129c24e"
        hash7 = "4d22b2d85b75ccf651f0ba85808482660a440bff"
        hash8 = "3463df6b33b26c1249207f6e004c0bbc31b31152"
        hash9 = "ca4c53eb86d5b920b321de573e212e31405707d5"
        hash10 = "a48e4dd017618ae2d46a753345594a5f57fbe869"

    strings:
        $pdb = "5\\bin\\bot.pdb" ascii

        $s1 = "pipe\\40DC244D-F62E-093E-8A91-736FF2FA2AA2" wide
        $s2 = "LoginName" ascii
		$s3 = "msicheck.cmd" ascii
        $s4 = "select id, hostname, usernamefield, passwordfield, encryptedusern" wide
        $s5 = "*temporary;*Cookies;*games;*system32;*program files;*\\windows\\;*\\System Volume Information" wide
        $s6 = "msicheck.cmd" ascii
        $s7 = "AppData\\Roaming\\Miranda"  wide 
        $s8 = "Local Settings\\Application Data" wide
	
	/*
	imul    ebx, esi
        imul    esi, 0BC8Fh
        mov     eax, edx
        and     eax, 3
        lea     eax, [ebp+eax*4+var_3C]
        xor     [eax], ebx
        inc     edx
        dec     [ebp+var_8]
	*/

        $chunk_1 = {0F AF DE 69 F6 ?? ?? ?? ?? 8B C2 83 E0 ?? 8D 44 85 ?? 31 18 42 FF 4D ??}   

    condition:
        uint16(0) == 0x5A4D 
        and filesize > 174KB 
        and (
            $pdb 
            or ( 4 of ($s*) and $chunk_1 )
        )
}








