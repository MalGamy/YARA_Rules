
rule Detect_Mimic_Ransomware: Mimic Ransomware   
{
     meta:
        description = "Detect_Mimic_Ransomware"
        author = "@MalGamy12"
        date = "2023-01-27"
        license = "DRL 1.1"
        hash = "08f8ae7f25949a742c7896cb76e37fb88c6a7a32398693ec6c2b3d9b488114be"
        hash = "136d05b5132adafc4c7616cd6902700de59f3f326c6931eb6b2f3b1f458c7457"
        hash = "1dea642abe3e27fd91c3db4e0293fb1f7510e14aed73e4ea36bf7299fd8e6506"
        hash = "2e96b55980a827011a7e0784ab95dcee53958a1bb19f5397080a434041bbeeea"
        hash = "30f2fe10229863c57d9aab97ec8b7a157ad3ff9ab0b2110bbb4859694b56923f"
        hash = "480fb2f6bcb1f394dc171ecbce88b9fa64df1491ec65859ee108f2e787b26e03"
        hash = "4a6f8bf2b989fa60daa6c720b2d388651dd8e4c60d0be04aaed4de0c3c064c8f"
        hash = "7ae4c5caf6cda7fa8862f64a74bd7f821b50d855d6403bde7bcbd7398b2c7d99"
        hash = "9c16211296f88e12538792124b62eb00830d0961e9ab24b825edb61bda8f564f"
        hash = "a1eeeeae0eb365ff9a00717846c4806785d55ed20f3f5cbf71cf6710d7913c51"
        hash = "b0c75e92e1fe98715f90b29475de998d0c8c50ca80ce1c141fc09d10a7b8e7ee"
        hash = "b68f469ed8d9deea15af325efc1a56ca8cb5c2b42f2423837a51160456ce0db5"
        hash = "bb28adc32ff1b9dcfaac6b7017b4896d2807b48080f9e6720afde3f89d69676c"
        hash = "bf6fa9b06115a8a4ff3982427ddc12215bd1a3d759ac84895b5fb66eaa568bff"
        hash = "c576f7f55c4c0304b290b15e70a638b037df15c69577cd6263329c73416e490e"
        hash = "c634378691a675acbf57e611b220e676eb19aa190f617c41a56f43ac48ae14c7"
        hash = "c71ce482cf50d59c92cfb1eae560711d47600541b2835182d6e46e0de302ca6c"
        hash = "e67d3682910cf1e7ece356860179ada8e847637a86c1e5f6898c48c956f04590"
        hash = "ed6cf30ee11b169a65c2a27c4178c5a07ff3515daa339033bf83041faa6f49c1"    

    strings:
        $s1 = "Reading tail" wide  
        $s2 = "GetWhiteList" wide
        $s3 = "KillServ" wide
        $s4 = "Kill Serv2" wide
        $s5 = "Kill proc" wide
        $s6 = "AntiKill" wide
        $s7 = "Protect..." wide
        $s8 = "AntiShutdown..." wide
        $s9 = "Found share" wide
        $s10 = "Enum shares on" wide
        $s11 = "Starting search on share" wide
        $s12 = "AddHost" wide
        $s13 = "CreateHostTable..." wide
        $s14 = "Network stack is outdated." wide
        $s15 = "Current IP" wide
   
    condition:
        uint16(0) == 0x5A4D and (10 of them)
}
