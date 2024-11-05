rule lzma : low {
  meta:
    description = "works with lzma files"
    ref         = "https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm"

  strings:
    $ref = "lzma" fullword
    $ref2 = "LZMA" fullword

  condition:
    any of them
}
