"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

const ITER = 100;
let input = Buffer.from("test");

function pad(num, size) {
    var s = '0000000000000000000000000000000000000000000000000000000000000000' + num;
    return s.substr(s.length-size);
}

let start = Date.now();
for (let i = ITER; i; -- i) {
  multiHashing.randomx(input, Buffer.from(pad(i, 64), 'hex'), 17);
  multiHashing.randomx(input, Buffer.from(pad(i, 64), 'hex'), 18);
  multiHashing.randomx(input, Buffer.from(pad(i, 64), 'hex'), 0);
}
let end = Date.now();
console.log("Perf: " + 1000 * ITER * 3 / (end - start) + " H/s");
