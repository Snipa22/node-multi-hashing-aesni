node-cryptonight-hashing
===============

Cryptonight hashing functions for node.js.


Algorithms
----------
* cryptonight (v0, v1, v2, r, half, xtl, msr, rto, xao, gpu, wow, rwz, zls, double)
* cryptonight-light (v0, v1)
* cryptonight-heavy (v0, xhv, tube)
* cryptonight-pico (trtl)

Installing locally and testing
-----
```
git clone --recursive https://github.com/SChernykh/node-cryptonight-hashing/
cd node-cryptonight-hashing
git checkout random_wow
git pull --recurse-submodules
cd RandomWOW && make && cd ..
npm install
node tests/test_random_wow.js
```

Credits
-------
* [XMrig](https://github.com/xmrig) - For advanced cryptonight implementations from [XMrig](https://github.com/xmrig/xmrig)
