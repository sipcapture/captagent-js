/* 
 *	NODEJS Captagent w/ HEP3 Support via HEP-js module
 *	(C) 2015 L. Mangani, QXIP BV
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *

 Example Usage:

	HEP3: 
		nodejs captagent.js -debug true -s 127.0.0.1 -p 9063 -i 2001

 Daemonize using forever:

	npm install forever -g
	forever start captagent.js

*/ 

var version = 'v0.4';
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

console.log('Starting JSAgent '+version);

/* NODE.JS Requirements */
var SIP = require('sipcore'),
    Cap = require('cap').Cap,
    decoders = require('cap').decoders,
    PROTOCOL = decoders.PROTOCOL,
    HEPjs = require('hep-js');

/* HEP OUT SOCKET */ 
var dgram = require('dgram'),
    socket = dgram.createSocket("udp4");

/* CAPTURE SOCKET */
var c = new Cap(),
    device = Cap.findDevice(),
    filter = bpf_filter,
    bufSize = 10 * 1024 * 1024,
    buffer = new Buffer(65535);

/* APP START */
console.log('Capturing from device '+device+ ' with BPF ('+bpf_filter+')');
console.log('Sending HEP3 Packets to '+hep_server+':'+hep_port+' with id '+hep_id);

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
