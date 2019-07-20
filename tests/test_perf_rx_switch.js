"use strict";
let multiHashing = require('../build/Release/cryptonight-hashing');

const ITER = 100;
let input = Buffer.from("test");

multiHashing.randomx(input, Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 17);
multiHashing.randomx(input, Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 18);
multiHashing.randomx(input, Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 0);

let start = Date.now();
for (let i = ITER; i; -- i) {
  multiHashing.randomx(input, Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 17);
  multiHashing.randomx(input, Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 18);
  multiHashing.randomx(input, Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), 0);
}
let end = Date.now();
console.log("Perf: " + 1000 * ITER * 3 / (end - start) + " H/s");
