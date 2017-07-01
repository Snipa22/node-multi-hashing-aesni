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

console.log(multiHashing.cryptonight(Buffer.from('This is a test')).toString('hex'))
/*
for (let hashType in hashes){
    if (hashes.hasOwnProperty(hashType)){
        let testsFailed = 0, testsPassed = 0;
        let lr = lineReader.createInterface({
            input: fs.createReadStream(hashes[hashType].file)
        });
        lr.on('line', function (line) {
            if (hashes[hashType].fileFormat === 'cn'){
                let line_data = line.split(' ');
                let hashed_data = hashes[hashType].function(Buffer.from(line_data[1])).toString('hex');
                if (line_data[0] !== hashed_data){
                    console.log('Expected: ' + line_data[0]);
                    console.log('Received: ' + hashed_data);
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
*/
