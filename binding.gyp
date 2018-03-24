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
                "monero/slow-hash.c"
            ],
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ],
            "cflags_c": [
                "-std=gnu11 -march=native -fPIC -m64"
            ],
            "cflags_cc": [
                "-std=gnu++11 -fPIC -m64"
            ]
        }
    ]
}
