{
    "targets": [
        {
            "target_name": "cryptonight-hashing",
            "sources": [
                "multihashing.cc",
                "xmrig/crypto/c_blake256.c",
                "xmrig/crypto/c_groestl.c",
                "xmrig/crypto/c_jh.c",
                "xmrig/crypto/c_skein.c",
                "xmrig/common/crypto/keccak.cpp"
            ],
            "include_dirs": [
                "xmrig",
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
