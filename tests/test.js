"use strict";
let multiHashing = require('../build/Release/multihashing');
let fs = require('fs');

let cn = multiHashing.cryptonight;
let cn_light = multiHashing.cryptonight_light;

let hashes = {};

let cn_hashes = fs.readFileSync('cryptonight.txt', "utf8");
let cn_hashes = fs.readFileSync('cryptonight_light.txt', "utf8");