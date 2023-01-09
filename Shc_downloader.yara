rule Shc_Downloader : Downloader
{
    meta:
	description = "detect_Shc_Downloader"
	author = "@malgamy12"
        date = "2022/1/4"
	license = "DRL 1.1"
        hash = "256ab7aa7b94c47ae6ad6ca8ebad7e2734ebaa21542934604eb7230143137342"
        

    strings:
        
        $op = {88 05 [4] 0F B6 05 [4] 0F B6 C0 48 98 0F B6 80 [4] 88 45 ?? 0F B6 05 [4] 02 45 ?? 88 05 [4] 0F B6 05 [4] 0F B6 C8 0F B6 05 [4] 0F B6 C0 48 98 0F B6 90 [4] 48 63 C1 88 90 [4] 0F B6 05 [4] 0F B6 C0 48 63 D0 0F B6 45 ?? 88 82 [4] 0F B6 05 [4] 0F B6 C0 48 98 0F B6 80 [4] 00 45 ?? 48 8B 45 ?? 0F B6 10 0F B6 45 ?? 48 98 0F B6 80 [4] 31 C2 48 8B 45 ?? 88 10}

    condition:
        all of them
}
