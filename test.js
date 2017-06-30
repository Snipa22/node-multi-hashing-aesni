let mh = require('./build/Release/multihashing');

mh.CNAsync('test', function(err, result){
    console.log(result.toString('hex'));
});
