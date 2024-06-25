
rule php_non_printable : medium {
  meta:
    description = "non-printable values unexpectedly passed to a function"
    credit = "Ported from https://github.com/jvoisin/php-malware-finder"
    hash_2024_2024_S3RV4N7_SHELL_crot = "2332fd44e88a571e821cf2d12bab44b45e503bc705d1f70c53ec63a197e4bb1a"
    hash_2023_0xShell_adminer = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
  strings:
    $ref = /(function|return|base64_decode).{,64}[^\x09-\x0d\x20-\x7E]{3}/
    $php = "<?php"
  condition:
    filesize < 5242880 and all of them
}
