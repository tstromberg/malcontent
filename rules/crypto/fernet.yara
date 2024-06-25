
rule crypto_fernet : medium {
  meta:
    description = "Supports Fernet (symmetric encryption)"
    hash_2024_2024_d3duct1v_s2 = "8c914dfa5cb7fd25d87ee802a48e8e63c090ceb400f0fd3cd0bf605bba36a4bd"
  strings:
    $ref = "fernet" fullword
    $ref2 = "Fernet" fullword
  condition:
    any of them
}
