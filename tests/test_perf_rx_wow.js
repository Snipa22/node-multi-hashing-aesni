"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

const ITER = 200;
let input = Buffer.from("test");

function pad(num, size) {
    var s = '0000000000000000000000000000000000000000000000000000000000000000' + num;
    return s.substr(s.length-size);
}

let start = Date.now();
for (let i = ITER; i; -- i) {
  multiHashing.randomx(input, Buffer.from(pad(i, 64), 'hex'), 17);
}
let end = Date.now();
console.log("Perf: " + 1000 * ITER / (end - start) + " H/s");
