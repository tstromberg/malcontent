
rule crontab_writer : medium {
  meta:
    description = "May use crontab to persist"
    hash_2023_usr_adxintrin_b = "a51a4ddcd092b102af94139252c898d7c1c48f322bae181bd99499a79c12c500"
    hash_2023_spirit = "26ba215bcd5d8a9003a904b0eac7dc10054dba7bea9a708668a5f6106fd73ced"
    hash_2023_ZIP_server = "b69738c655dee0071b1ce37ab5227018ebce01ba5e90d28bd82d63c46e9e63a4"
  strings:
    $c_etc_crontab = /\/etc\/cron[\/\w\.]{0,32}/
    $c_crontab_e = "crontab -"
    $c_var_spool_cron = "/var/spool/cron"
    $not_usage = "usage: cron"
  condition:
    filesize < 52428800 and any of ($c*) and none of ($not*)
}

rule crontab_entry : high {
  meta:
    description = "Uses crontab to persist"
    hash_2024_2024_Kaiji_eight_nebraska_autumn_illinois = "38edb3ab96a6aa6c3f4de3590dfb63ca44ddf29d5579ef3b12de326c86145537"
    hash_2024_2024_Spinning_YARN_yarn_fragments = "723326f8551f2a92ccceeec93859f58df380a3212e7510bc64181f2a0743231c"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
  strings:
    $crontab = "crontab"
    $repeat_every_minutes = /\*\/\d \* \* \* \*/
    $repeat_every_minute = "* * * * *"
    $repeat_hourly = /\d \* \* \* \*/
    $repeat_root = "* * * * root"
    $repeat_daily = "@daily"
  condition:
    filesize < 52428800 and $crontab and any of ($repeat*)
}

rule crontab_danger_path : high {
  meta:
    ref = "https://blog.xlab.qianxin.com/mirai-nomi-en/"
    description = "Starts from a dangerous-looking path"
    hash_2023_Linux_Malware_Samples_741a = "741af7d54a95dd3b4497c73001e7b2ba1f607d19d63068b611505f9ce14c7776"
    hash_2023_Linux_Malware_Samples_ee0e = "ee0e8516bfc431cb103f16117b9426c79263e279dc46bece5d4b96ddac9a5e90"
  strings:
    $any_val = /\* \* \* \/(boot|var|tmp|dev|root)\/[\/\.\w\ \-]{0,64}/
    $reboot_val = /@reboot \/(boot|var|tmp|dev|root)\/[\/\.\w\ \-]{0,64}/
  condition:
    filesize < 104857600 and any of them
}
