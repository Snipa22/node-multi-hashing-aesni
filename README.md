node-cryptonight-hashing
===============

Cryptonight hashing functions for node.js.


Algorithms
----------
* cryptonight
* cryptonight-light

Usage
-----

Install

```bash
npm install https://github.com/MoneroOcean/node-cryptonight-hashing.git
```

So far this native Node.js addon can do the following hashing algos

```javascript
var multiHashing = require('cryptonight-hashing');

var algorithms = ['cryptonight', 'cryptonight-light' ];

var data = new Buffer("7000000001e980924e4e1109230383e66d62945ff8e749903bea4336755c00000000000051928aff1b4d72416173a8c3948159a09a73ac3bb556aa6bfbcad1a85da7f4c1d13350531e24031b939b9e2b", "hex");

var hashedData = algorithms.map(function(algo){
    if (algo === 'scryptjane'){
        //scryptjane needs block.nTime and nChainStartTime (found in coin source)
        var yaCoinChainStartTime = 1367991200;
        var nTime = Math.round(Date.now() / 1000);
        return multiHashing[algo](data, nTime, yaCoinChainStartTime);
    }
    else{
        return multiHashing[algo](data);
    }
});


console.log(hashedData);
//<SlowBuffer 0b de 16 ef 2d 92 e4 35 65 c6 6c d8 92 d9 66 b4 3d 65 ..... >


```

Credits
-------
* [The Monero Project](https://github.com/monero-project) - For reference cryptonight implementations from [Monero](https://github.com/monero-project/monero)
* [XMrig](https://github.com/xmrig) - For advanced cryptonight implementations from [XMrig](https://github.com/xmrig/xmrig)
