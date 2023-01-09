rule Windows_Trojan_Formbook: FormBook_malware
{
    meta:
        author = "@malgamy12"
        date = "2022-11-8"
	license = "DRL 1.1"
        sample1 = "9fc57307d1cce6f6d8946a7dae41447b"
        sample2 = "0f4a7fa6e654b48c0334b8b88410eaed"
        sample3 = "0a25d588340300461738a677d0b53cd2"
        sample4 = "57d7bd215e4c4d03d73addec72936334"
        sample5 = "c943e31f7927683dc1b628f0972e801b"
        sample6 = "db87f238bb4e972ef8c0b94779798fa9"
        sample7 = "8ba1449ee35200556ecd88f23a35863a"
        sample8 = "8ca20642318337816d5db9666e004172"
        sample9 = "280f7c87c98346102980c514d2dd25c8"

    strings:
        $a1 = { 8B 45 ?? BA ?? [3] 8B CF D3 E2 84 14 03 74 ?? 8B 4D ?? 31 0E 8B 55 ?? 31 56 ?? 8B 4D ?? 8B 55 ?? 31 4E ?? 31 56 ?? }
			
        $a2 = { 0F B6 3A 8B C8 C1 E9 ?? 33 CF 81 E1 [4] C1 E0 ?? 33 84 8D [4] 42 4E }
        
        $a3 = { 1A D2 80 E2 ?? 80 C2 ?? EB ?? 80 FA ?? 75 ?? 8A D0 80 E2 ?? }

        $a4 = { 80 E2 ?? F6 DA 1A D2 80 E2 ?? 80 C2 ?? }

    condition:
         3 of them
}

