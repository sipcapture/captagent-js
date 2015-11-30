[![Dependency Status](https://david-dm.org/sipcapture/captagent-js.svg)](https://david-dm.org/sipcapture/captagent-js) 
![HEP](https://img.shields.io/badge/powered%20by-HEP-blue.svg)

[![Logo](https://camo.githubusercontent.com/aa3bd3f9a7121637f58af5d2fee969815b250737/687474703a2f2f692e696d6775722e636f6d2f336b4549522e706e67)](http://sipcapture.org)

# captagent-js
This is a fully working **PROTOTYPE** Captagent implementation in NodeJS w/ HEP3 and ES Bulk API Support output.

Captagent-js can sniff SIP packets and send HEP3 encapsulated packets to a HOMER/PCAPTURE server - It can optionally send JSON parsed SIP packets to an Elasticsearch cluster for indexing. 

HEP3/EEP functionality support is provided by nodejs module [HEP-js](https://www.npmjs.com/package/hep-js)

For more information about HEP and SIPCAPTURE Projects, please visit [http://sipcapture.org](http://sipcapture.org)

### Requirements:
```
	npm install cap
	npm install sipcore
	npm install hep-js
	npm install elasticsearch
```

### Example Usage:

	HEP3: 
		nodejs captagent-es.js -s 127.0.0.1 -p 9063 -i 2001 -P myHep
	ES:   
		nodejs captagent-es.js -debug true -ES 'https://test.facetflow.io:443' -t 15

### Daemonize process:

	npm install forever -g
	forever start captagent.js

