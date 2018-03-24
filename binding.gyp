{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",
                "monero/*.c"
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
