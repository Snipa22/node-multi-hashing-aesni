{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",
                "monero/aesb.c",
                "monero/blake256.c",
                "monero/groestl.c",
                "monero/hash-extra-blake.c",
                "monero/hash-extra-groestl.c",
                "monero/hash-extra-jh.c",
                "monero/hash-extra-skein.c",
                "monero/hash.c",
                "monero/jh.c",
                "monero/keccak.c",
                "monero/oaes_lib.c",
                "monero/skein.c",
                "monero/slow-hash.c",
                "xmrig/crypto/c_blake256.c",
                "xmrig/crypto/c_groestl.c",
                "xmrig/crypto/c_jh.c",
                "xmrig/crypto/c_keccak.c",
                "xmrig/crypto/c_skein.c"
            ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ],
            "cflags_c": [
                "-std=gnu11 -march=native -fPIC -m64 -DNDEBUG -Ofast -funroll-loops -fvariable-expansion-in-unroller -ftree-loop-if-convert-stores -fmerge-all-constants -fbranch-target-load-optimize2"
            ],
            "cflags_cc": [
                "-std=gnu++11 -march=native -fPIC -m64 -DNDEBUG -Ofast -s -funroll-loops -fvariable-expansion-in-unroller -ftree-loop-if-convert-stores -fmerge-all-constants -fbranch-target-load-optimize2"
            ]
        }
    ]
}
