/* 
	NODEJS Captagent w/ HEP3 Support via HEP-js module
	(C) 2015 SIPCAPTURE.ORG, QXIP BV


 Requirements:

	npm install cap
	npm install sipcore
	npm install hep-js
	npm install elasticsearch


 Example Usage:

	HEP3: 
		nodejs captagent-es.js -debug true -s 127.0.0.1 -p 9063 -i 2001
	ES:   
		nodejs captagent-es.js -debug true -ES 'https://test.facetflow.io:443' -t 15

 Daemonize using forever:

	npm install forever -g
	forever start captagent.js

*/ 

var version = 'v0.3';
var debug = false;
var sipdebug = false;
var stats = {rcvd: 0, parsed: 0, hepsent: 0, err: 0, heperr: 0 }; 

/* HELP MENU */
if(process.argv.indexOf("-h") != -1){ 
	console.log('NodeAgent is an HEP3 Capture Agent implementation for HOMER / SIPCAPTURE');
	console.log('For more information please visit: http://sipcapture.org ');
	console.log('Usage:');
	console.log();
	console.log('      -r:     	BPF Capture filter (ie: port 5060)');
	console.log();
	console.log('      -s:     	HEP3 Collector IP');
	console.log('      -p:     	HEP3 Collector Port');
	console.log('      -i:     	HEP3 Agent ID');
	console.log('      -P:     	HEP3 Password');
	console.log();
	console.log('      -ES:    	ES _Bulk API IP    (ie: 127.0.0.1) ');
	console.log('      -EP:    	ES _Bulk API Port  (ie: 443) ');
	console.log('      -EI:    	ES _Bulk API Index (ie: captagent)');
	console.log('      -ET:    	ES _Bulk API Type  (ie: captagent)');
	console.log('      -EU:    	ES _Bulk API Auth  (ie: user:pass)');
	console.log('      -t:     	ES _Bulk Frequency (in seconds)');
	console.log();
	console.log('      -debug: 	Debug Internals    (ie: -debug true)');
	console.log('      CRTL-C: 	Exit');
	console.log();
	process.exit();
}


/* Settings Section */

	// CAPTURE ARGS & DEFAULTS
	var bpf_filter = 'port 5060';
	if(process.argv.indexOf("-r") != -1){ 
	    bpf_filter = process.argv[process.argv.indexOf("-r") + 1];
	}
	if(process.argv.indexOf("-debug") != -1){ 
	   debug = process.argv[process.argv.indexOf("-debug") + 1];
	}

	// HEP ARGS & DEFAULTS
	var hep_server = 'localhost';
	if(process.argv.indexOf("-s") != -1){ 
	    hep_server = process.argv[process.argv.indexOf("-s") + 1];
	}
	var hep_port = 9063;
	if(process.argv.indexOf("-p") != -1){ 
	    hep_port = process.argv[process.argv.indexOf("-p") + 1];
	}
	var hep_id = '2001';
	if(process.argv.indexOf("-i") != -1){ 
	    hep_id = process.argv[process.argv.indexOf("-i") + 1];
	}
	var hep_pass = 'myHep6';
	if(process.argv.indexOf("-P") != -1){ 
	    hep_pass = process.argv[process.argv.indexOf("-P") + 1];
	}

	// ES ARGS & DEFAULTS (experimental, HTTPS default)
	var es_on = false;
	var es_url = 'http://127.0.0.1:9200'; 
	var es_user = ''; 

	if(process.argv.indexOf("-ES") != -1){ 
	    es_url = process.argv[process.argv.indexOf("-ES") + 1];
	    es_on = true;
	}

	var es_index = 'captagent'; 
	if(process.argv.indexOf("-EI") != -1){ 
	    es_index = process.argv[process.argv.indexOf("-EI") + 1];
	}
	var es_type = 'captagent'; 
	if(process.argv.indexOf("-ET") != -1){ 
	    es_type = process.argv[process.argv.indexOf("-ET") + 1];
	}

	if(process.argv.indexOf("-EU") != -1){ 
	    es_user = process.argv[process.argv.indexOf("-EU") + 1];
	}

	var es_timeout = 30; 
	if(process.argv.indexOf("-t") != -1){ 
	    es_timeout = parseInt(process.argv[process.argv.indexOf("-t") + 1]);
	}

	var es_interval = es_timeout * 1000;
	// var es_buffer;


console.log('Starting JSAgent '+version);

/* NODE.JS Requirements */

var SIP = require('sipcore');
var Cap = require('cap').Cap,
    decoders = require('cap').decoders,
    PROTOCOL = decoders.PROTOCOL;

var HEPjs = require('hep-js');

/* ELASTICSEARCH Configuration */
if (es_on) { 
	var elasticsearch = require('elasticsearch');
	if (es_user.length > 1) { es_url = es_url.replace('://', '://'+es_user+'@'); }

	var client = new elasticsearch.Client({
	  hosts: [
	      es_url
	  ]
	});
}


/* HEP OUT SOCKET */ 

var dgram = require('dgram');
var socket = dgram.createSocket("udp4");



/* CAPTURE SOCKET */

var c = new Cap(),
    device = Cap.findDevice(),
    // filter = 'port 5060',
    filter = bpf_filter,
    bufSize = 10 * 1024 * 1024,
    buffer = new Buffer(65535);


/* HTTP SOCKET */
if (es_on){
        var es_buffer = '';
	setInterval(function() {
	  if (debug) console.log("HTTP: Sending Statistics...");
	  if (buffer.length > 1) {
	  	// Send buffer and clear
		sendHTTP(es_buffer+'\n');
		es_buffer = ''; 
	  }
	}, es_interval);
}



/* APP START */

console.log('Capturing from device '+device+ ' with BPF ('+bpf_filter+')');
console.log('Sending HEP3 Packets to '+hep_server+':'+hep_port+' with id '+hep_id);
if (es_on) console.log('Sending JSON Packets to '+es_url+'  _Bulk API with type '+es_type);

var linkType = c.open(device, filter, bufSize, buffer);

c.setMinBytes && c.setMinBytes(0);

c.on('packet', function(nbytes, trunc) {
  if (debug) console.log('packet: length ' + nbytes + ' bytes, truncated? '
              + (trunc ? 'yes' : 'no'));

  stats.rcvd++;
  var hep_proto = { "type": "HEP", "version": 3, "payload_type": "SIP", "captureId": hep_id, "capturePass": hep_pass, "ip_family": 2};

  // raw packet data === buffer.slice(0, nbytes)

  if (linkType === 'ETHERNET') {
    var ret = decoders.Ethernet(buffer);

	var datenow =  new Date().getTime();
	hep_proto.time_sec = Math.floor(datenow / 1000);
	hep_proto.time_usec = datenow - (hep_proto.time_sec*1000);

    if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
      if (debug) console.log('Decoding IPv4 ...');

      ret = decoders.IPV4(buffer, ret.offset);
      if (debug) console.log('from: ' + ret.info.srcaddr + ' to ' + ret.info.dstaddr);

      if (ret.info.protocol === PROTOCOL.IP.TCP) {
	/* TCP DECODE */
        var datalen = ret.info.totallen - ret.hdrlen;
        if (debug) console.log('Decoding TCP ...');

        var tcpret = decoders.TCP(buffer, ret.offset);
        if (debug) console.log(' TCP from: ' + ret.info.srcip + ':' + tcpret.info.srcport + ' to: ' + ret.info.dstaddr + ':' + tcpret.info.dstport);
        datalen -= tcpret.hdrlen;
        // if (debug) console.log(buffer.toString('binary', tcpret.offset, tcpret.offset + datalen));
	var msg = buffer.toString('binary', tcpret.offset, tcpret.offset + datalen);

        // Build HEP3
	hep_proto.ip_family = 2;
        hep_proto.protocol = 6;
	hep_proto.proto_type = 1;
        hep_proto.srcIp = ret.info.srcaddr;
        hep_proto.dstIp = ret.info.dstaddr;
        hep_proto.srcPort = tcpret.info.srcport;
        hep_proto.dstPort = tcpret.info.dstport;

	// Ship to parser
	parseSIP(msg, hep_proto);

      } else if (ret.info.protocol === PROTOCOL.IP.UDP) {
	/* UDP DECODE */
        if (debug) console.log('Decoding UDP ...');
        var udpret = decoders.UDP(buffer, ret.offset);
        if (debug) console.log(' UDP from: ' + ret.info.srcaddr + ':' + udpret.info.srcport + ' to: ' + ret.info.dstaddr+ ':' + udpret.info.dstport);
        // if (debug) console.log(buffer.toString('binary', udpret.offset, udpret.offset + udpret.info.length));
	var msg = buffer.toString('binary', udpret.offset, udpret.offset + udpret.info.length);

        // Build HEP3
	hep_proto.ip_family = 2;
        hep_proto.protocol = 17;
	hep_proto.proto_type = 1;
        hep_proto.srcIp = ret.info.srcaddr;
        hep_proto.dstIp = ret.info.dstaddr;
        hep_proto.srcPort = udpret.info.srcport;
        hep_proto.dstPort = udpret.info.dstport;

	// Ship to parser
	parseSIP(msg, hep_proto);

      } else
        if (debug) console.log('Unsupported IPv4 protocol: ' + PROTOCOL.IP[ret.info.protocol]);
	stats.err++;
    } else
      	if (debug) console.log('Unsupported Ethertype: ' + PROTOCOL.ETHERNET[ret.info.type]);
	stats.err++;
  }
});


/* SIP Parsing */

var parseSIP = function(msg, rcinfo){
	try {
		var sipmsg = SIP.parse(msg);
		if (sipdebug) console.log(sipmsg);
		if (debug) console.log('CSeq: '+sipmsg.headers.cseq);
		stats.parsed++;
			// SEND HEP3 Packet
			sendHEP3(sipmsg,msg, rcinfo);

			if (es_on) {
				// PARSE USERS/URI for Elasticsearch Indexing
	                	sipmsg.headers["from_uri"] = sipmsg.headers.from.match(/^(<sip)(.*)>/)[0];
	                	sipmsg.headers["to_uri"] = sipmsg.headers.to.match(/^(<sip)(.*)>/)[0];
	                	sipmsg.headers["from_user"] = sipmsg.headers.from.match(/<sip:(.*?)@/)[1] ;
	                	sipmsg.headers["to_user"] = sipmsg.headers.to.match(/<sip:(.*?)@/)[1] ;
	                	// SESSION METHOD
	                	sipmsg.headers["sess_method"] = sipmsg.headers.cseq.replace(/[^A-Za-z\s!?]/g,'');
	                	// INJECT NETWORK/HEP Headers
	                	sipmsg['hep'] = rcinfo;

				bufferSIP(sipmsg);
			}
	} 
	catch (e) {
		if (debug) console.log(e);
		var sipmsg = false;
		stats.err++;
	}
}


/* HEP3 Socket OUT */

var sendHEP3 = function(sipmsg,msg, rcinfo){
	if (sipmsg) {
		try {
			if (debug) console.log('Sending HEP3 Packet...');
			var hep_message = HEPjs.encapsulate(msg,rcinfo);
			if (hep_message) {
				socket = getSocket('udp4'); 
				// socket.send(hep_message, 0, hep_message.length, 9063, "localhost", function(err) {
				socket.send(hep_message, 0, hep_message.length, hep_port, hep_server, function(err) {
					stats.hepsent++;
				  	// socket.close();
				});
			}
		} 
		catch (e) {
			console.log('HEP3 Error sending!');
			console.log(e);
			stats.heperr++;
		}
	}
}



/* JSON _Bulk Buffer */

var bufferSIP = function(data){
        if (debug) console.log('Buffering SIP....');
        var now = new Date().toISOString().substring(0, 10).replace(/-/g,'.');
        data["@timestamp"] = new Date().toISOString().slice(0, 19) + 'Z';
        es_buffer += '{"index":{"_index":"'+es_index+'-'+now+'","_type":"'+es_type+'"}}\n'+JSON.stringify(data)+'\n';
}



/* HTTP Socket OUT */

var sendHTTP = function(xbuffer){
	if (xbuffer && xbuffer.length > 1) {
		try {
                        if (debug) console.log('Sending HTTP JSON Packet...');
                        // post the data to Bulk using ES Client
			client.bulk({
 				body: xbuffer 
			}, function (err, resp) {
				if (err) console.log('Err: ',JSON.stringify(err) );
				else if (debug) console.log('Resp: ',JSON.stringify(resp) );
			});

		} 
		catch (e) {
			console.log('HTTP Error sending!');
			console.log(e);
			stats.heperr++;
		}
	}
}


/* UDP Socket Handler */

var getSocket = function (type) {
    if (undefined === socket) {
        socket = dgram.createSocket(type);
        socket.on('error', socketErrorHandler);
        /**
         * Handles socket's 'close' event,
         * recover socket in case of unplanned closing.
         */
        var socketCloseHandler = function () {
            if (socketUsers > 0) {
                socket = undefined;
                --socketUsers;
                getSocket(type);
            }
        };
        socket.on('close', socketCloseHandler);
    }
    return socket;
}


/* Stats & Kill Thread */

var exit = false;

process.on('SIGINT', function() {
    console.log();
    if (exit) {
	if (es_buffer && es_buffer.length > 1) sendHTTP(es_buffer+'\n');
    	console.log("Exiting...");
        process.exit();
    } else {
        console.log('Statistics:', stats);
	if (es_buffer && es_buffer.length > 1) sendHTTP(es_buffer+'\n');
    	console.log("Press CTRL-C within 2 seconds to Exit...");
        exit = true;
	setTimeout(function () {
    	  // console.log("Continuing...");
	  exit = false;
	}, 2000)
    }
});
