
rule hidden_crontab : critical {
  meta:
    description = "persists via a hidden crontab entry"
    hash_2024_2024_Kaiji_eight_nebraska_autumn_illinois = "38edb3ab96a6aa6c3f4de3590dfb63ca44ddf29d5579ef3b12de326c86145537"
    hash_2023_Linux_Malware_Samples_741a = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2023_Linux_Malware_Samples_ee0e = "ee0e8516bfc431cb103f16117b9426c79263e279dc46bece5d4b96ddac9a5e90"
  strings:
    $crontab = "crontab"
    $c_periodic_with_user = /\*[\/\d]{0,3} \* \* \* \* [a-z]{1,12} [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_periodic = /\*[\/\d]{0,3} \* \* \* \* [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_nickname_with_user = /\@(reboot|yearly|annually|monthly|weekly|daily|hourly) [a-z]{1,12} [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
    $c_nickname = /\@(reboot|yearly|annually|monthly|weekly|daily|hourly) [\$\w\/]{0,32}\/\.[\%\w\.\-\/]{0,16}/
  condition:
    $crontab and any of ($c_*)
}
