'use strict';

const iniParser = require('./libs/iniParser')
const logging = require('./libs/logging')
const args = require('minimist')(process.argv.slice(2));
const bodyParser = require('body-parser')

const fs = require("fs");
const http    = require('http')
const express = require('express')
const app     = express();

const path    = require('path')
const moment    = require('moment')
const events = require("events")

// EventEmitter = events.EventEmitter;
// var originalAddListener = EventEmitter.prototype.addListener;
// EventEmitter.prototype.addListener = function (type, listener) {
//     if (this.listenerCount(this, type) >= 10) {
//         console.log(type);
        
//     }
//     originalAddListener.apply(this, arguments);
// }

process.env.TZ = 'Asia/Jakarta'
// default config if config file is not provided
let config = {
    log: {
        path: "var/log/",
        level: "debug"
    }
}

if (args.h || args.help) {
    // TODO: print USAGE
    console.log("Usage: node " + __filename + " --config");
    process.exit(-1);
}

// overwrite default config with config file
let configFile = args.c || args.config || './configs/config.ini'
config = iniParser.init(config, configFile, args)
config.log.level = args.logLevel || config.log.level

const take_port = config.app.port;
const port = take_port || process.env.PORT;

// Initialize logging library
logging.init({
    path: config.log.path,
    level: config.log.level
})

var server = http.createServer(app);
// Pass a http.Server instance to the listen method
var io = require('socket.io').listen(server);

// The server should start listening
server.listen(port);
console.log('[server] ARP Poisoning Detector running on ' + port);

// Register the index route of your app that returns the HTML file
app.get('/monitoring', function (req, res) {
    console.log("New Client Connected");
    res.sendFile(__dirname + '/public/output.html');
});

// Expose the node_modules folder as static resources (to access socket.io.js in the browser)
app.use('/assets', [
    express.static(__dirname + '/node_modules/jquery/dist/'),
    express.static(__dirname + '/node_modules/moment/'),
    express.static(__dirname + '/node_modules/socket.io-client/dist/')
]);

var ARP_Discovery = require('./libs/arp-discovery')
var discoverNetwork = []
var lostNetwork = []
var foundNetwork = []
var updateNetwork = []
var arpTable = new ARP_Discovery({timeout:1000, flood_interval: 300, resolve_macvendor:true});

arpTable.on('error', function(err){
  console.log(err);
});

console.log('Initiazation Socket...');
console.log('Getting ARP Table...');

arpTable.on('success', function(res) {
    if (!res) {
        console.log('!res');
        return;
    }

    discoverNetwork.length = 0 //empty the array before refresh    
    for (let key in res) {
        if (res.hasOwnProperty(key)) {

            discoverNetwork.push(res[key])
        }
    }
    io.sockets.emit('discoverNet', discoverNetwork);
    
}); 

// Monitoring :
arpTable.on('lost', function(lost){
    lostNetwork.length = 0 //empty the array before refresh
    for (let key in lost) {
        if (lost.hasOwnProperty(key)) {
            lostNetwork.push(lost[key])
        }
    }
    io.sockets.emit('lostNet', lostNetwork);
});

arpTable.on('found', function(found)
{
    foundNetwork.length = 0 //empty the array before refresh
    for (let key in found) {
        if (found.hasOwnProperty(key)) {
            foundNetwork.push(found[key])
        }
    }
    io.sockets.emit('foundNet', foundNetwork);    
});

arpTable.on('update', function(update){
    updateNetwork.length = 0 //empty the array before refresh
    for (let key in update) {
        if (update.hasOwnProperty(key)) {
            updateNetwork.push(update[key])
        }
    }
    
    io.sockets.emit('updateNet', updateNetwork);
});

arpTable.discover();
console.log('Start Capturing packet....')
var listenPacket = require('./libs/detect-spoofer')

listenPacket(iniParser.get().interface.name, function () {
  console.log('Start Capturing packet....')
})
// arpListener.listenPacket('enp0s3')
fs.truncate('./var/log/logArpSpoof.log', 0, function(){console.log('done')})
var detectedArp = fs.readFileSync('./var/log/logArpSpoof.log').toString('utf8');
io.sockets.emit('detectedArp', JSON.stringify(detectedArp))

// Handle connection
io.sockets.on('connection', function (socket) {
    
    socket.emit('discoverNet', discoverNetwork);
    socket.emit('lostNet', lostNetwork);    
    socket.emit('detectedArp', detectedArp);    
    
});

arpTable.monitor(30000);
