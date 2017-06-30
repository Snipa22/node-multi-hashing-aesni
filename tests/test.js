"use strict";
let multiHashing = require('../build/Release/multihashing');
let fs = require('fs');
let lineReader = require('readline');

let hashes = {
    'CryptoNight': {
        'file': 'cryptonight.txt',
        'fileFormat': 'cn',
        'function': multiHashing.cryptonight
    },
    'CryptoNight-Light': {
        'file': 'cryptonight_light.txt',
        'fileFormat': 'cn',
        'function': multiHashing.cryptonight_light
    }
};

for (let hashType in hashes){
    if (hashes.hasOwnProperty(hashType)){
        let testsFailed = 0, testsPassed = 0;
        let lr = lineReader.createInterface({
            input: fs.createReadStream(hashes[hashType].file)
        });
        lr.on('line', function (line) {
            if (hashes[hashType].fileFormat === 'cn'){
                let line_data = line.split(' ');
                if (line_data[0] !== hashes[hashType].function(Buffer.from(line_data[1])).toString('hex')){
                    testsFailed += 1;
                } else {
                    testsPassed += 1;
                }
            }
        });
        lr.on('close', function(){
            if (testsFailed > 0){
                console.log(testsFailed + '/' + (testsPassed + testsFailed) + ' tests failed on: ' + hashType);
            } else {
                console.log(testsPassed + ' tests passed on: ' +hashType);
            }
        });
    }
}
