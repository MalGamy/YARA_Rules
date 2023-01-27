rule Detect_ViceSociety_Ransomware: ViceSociety Ransomware   
{
	meta:
	   description = "Detect_ViceSociety_Ransomware"
	   author = "@MalGamy12"
	   date = "2023-01-25"
	   license = "DRL 1.1"
	   hash1 = "7c26041f8a63636d43a196f5298c2ab694a7fcbfa456278aa51757fd82c237d4"
           hash2 = "8843bafbb4a43a6c7a77c62a513908d1e2352ae5f58bd8bfa6d604bc795dcd12"
           hash3 = "1df9b68a8642e6d1fcb786d90a1be8d9633ee3d49a08a5e79174c7150061faa8"
           hash4 = "da0332ace0a9ccdc43de66556adb98947e64ebdf8b3289e2291016215d8c5b4c"
           hash5 = "7b379458349f338d22093bb634b60b867d7fd1873cbd7c65c445f08e73cbb1f6"
           hash6 = "4dabb914b8a29506e1eced1d0467c34107767f10fdefa08c40112b2e6fc32e41"
           hash7 = "f366e079116a11c618edcb3e8bf24bcd2ffe3f72a6776981bf1af7381e504d61"
           hash8 = "326a159fc2e7f29ca1a4c9a64d45b76a4a072bc39ba864c49d804229c5f6d796"
           hash9 = "432f91e194973dc214d772d39d228748439839b268f6a62ad529cb4f00203aaa"
           


    strings:

          $op1 = {41 01 ED 01 FE 44 01 C3 44 31 E9 31 F2 31 D8 C1 C1 ?? C1 C2 ?? 41 01 CB 41 01 D1 C1 C0 ?? 44 31 DD 44 31 CF 41 01 C4 C1 C5 ?? C1 C7 ?? 45 31 E0 41 01 ED 01 FE 41 C1 C0 ?? 44 31 E9 31 F2 44 01 C3 C1 C1 ?? C1 C2 ?? 31 D8 41 01 CB 41 01 D1 44 31 DD 44 31 CF 44 89 4C 24 ?? C1 C5 ?? C1 C7 ?? 44 89 5C 24 ?? C1 C0 ?? 45 01 FA 41 01 FD 45 31 D6 41 01 C4 45 89 F1 44 8B 74 24 ?? 45 31 E0 41 C1 C1 ?? 41 C1 C0 ?? 44 01 C6 31 F1 45 01 CE C1 C1 ?? 45 31 F7 45 89 F3 41 C1 C7 ?? 45 01 FA 45 31 D1 41 C1 C1 ?? 45 01 CB 45 31 E9 41 C1 C1 ?? 45 31 DF 41 01 CB 45 01 CC 41 C1 C7 ?? 44 31 E7 C1 C7 ?? 41 01 FD 45 31 E9 45 89 CE 44 8B 4C 24 ?? 41 C1 C6 ?? 45 01 F4 44 31 E7 C1 C7 ?? 45 31 D8 44 01 FB 41 C1 C0 ?? 41 01 EA 31 DA 44 01 C6 44 31 D0 C1 C2 ?? 31 F1 C1 C0 ?? C1 C1 ?? 41 01 C1 41 01 CB 44 31 CD 45 31 D8 44 89 5C 24 ?? 44 8B 5C 24 ?? C1 C5 ?? 41 01 EA 41 C1 C0 ?? 44 31 D0 C1 C0 ?? 41 01 D3 41 01 C1 45 31 DF 44 31 CD 41 C1 C7 ?? C1 C5 ?? 44 01 FB 31 DA C1 C2 ?? 41 01 D3 45 31 DF 41 C1 C7 ?? 83 6C 24}
          $op2 = {48 63 D2 48 8D 14 91 42 8B 0C A8 46 0F B6 04 A0 44 8B 14 B8 81 E1 [4] 44 09 C1 44 8B 04 A8 33 0A 41 81 E2 [4] 41 81 E0 [4] 45 09 D0 41 31 C8 8B 4C 24 ?? 41 0F C8 45 89 01 44 8B 44 24 ?? 8B 0C 88 46 0F B6 04 80 81 E1 [4] 44 09 C1 44 8B 04 24 33 4A ?? 46 8B 04 80 45 89 C2 44 8B 44 24 ?? 41 81 E2 [4] 46 8B 04 80 41 81 E0 [4] 45 09 D0 44 31 C1 46 0F B6 04 B8 0F C9 41 89 49 ?? 8B 4C 24 ?? 44 8B 7C 24 ?? 8B 0C 88 46 8B 14 B8 81 E1 [4] 44 09 C1 46 8B 04 98 41 89 F3 41 81 E2 [4] 33 4A ?? 41 81 E0 [4] 45 09 D0 44 31 C1}
          $op3 = {0F B7 0A 44 89 C7 48 83 C2 ?? 89 C8 D3 E7 66 C1 E8 ?? 0F B7 C0 41 31 3C 81}
        
    condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of them 
}









