#!/bin/bash -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR
node compare_both.js
node test.js
node test_async.js
node test_sync-1.js
node test_sync.js
node test_sync_light.js
node test_perf.js
node test_perf_light.js
