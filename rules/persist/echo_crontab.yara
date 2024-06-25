
rule echo_crontab : high {
  meta:
    hash_2024_2024_Kaiji_eight_nebraska_autumn_illinois = "38edb3ab96a6aa6c3f4de3590dfb63ca44ddf29d5579ef3b12de326c86145537"
    hash_2023_Downloads_d920 = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"
    hash_2020_Enigma = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"
  strings:
    $echo = /echo.{0,10}\* \* \* \*.{0,24}cron[\w\/ \-]{0,16}/
  condition:
    $echo
}
