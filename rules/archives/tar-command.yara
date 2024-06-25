
rule executable_calls_archive_tool : high {
  meta:
    description = "command shells out to tar"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
    hash_2021_CDDS_UserAgent_v2019 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
  strings:
    $a_tar_c = "tar -c"
    $a_tar_rX = "tar -r -X"
    $a_tar_T = "tar -T"
    $hash_bang = "#!"
  condition:
    any of ($a*) and not $hash_bang in (0..2)
}
