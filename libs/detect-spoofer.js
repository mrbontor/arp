const fs = require('fs')
const iniParser = require('./iniParser')
const util = require('util')
const pcap = require('pcap')
const macaddress = require('macaddress')
const ip = require('ip')
const tcp = require('./tcpParser')
const logging = require('./logging')
const utilDate = require('./utils')
const location_db = './data/db' 
const my_mac = macaddress.one(mac => {})
const pendingSYNs = {}

let config = iniParser.get()
if (!fs.existsSync(location_db)){
    fs.writeFileSync(location_db, JSON.stringify({}));
}
const validatedHostsRaw = fs.readFileSync(location_db);
const validatedHosts = JSON.parse(validatedHostsRaw);

var message = {
    message: '', date: ''
}

function listenPacket(iface) {
    let pcapSession = pcap.createSession(iface, 'arp or (tcp dst port 31337)')
    
    pcapSession.on('packet', function (rawPacket) {
        let packet = pcap.decode.packet(rawPacket)
        if(packet.payload.ethertype == 0x0800){//TCP
            traceTCPPacket(packet.payload) //line header packets
        }else if (packet.payload.ethertype == 0x0806){//ARP
            traceARPPacket(packet.payload) //line header packets
        }        
    })
}

function traceARPPacket(rawPacket){
    let arpPacket = rawPacket.payload; //arp packet
    if(!checkARPPackets(rawPacket)){
        return
    }
    
    if(!checkHeaders(rawPacket)){
        message = {
            message: `Mac-ARP Header Mismatch : ${macAddressConverter(arpPacket.sender_ha.addr)} ' spoofing '  ${arpPacket.sender_pa.addr.join('.')}`,
            date: utilDate()
        }
        logger(message, 'debug')
        return        
    }
    validateHost(arpPacket.sender_pa.addr.join('.'), macAddressConverter(arpPacket.sender_ha.addr))
}

//some RST or ACK arrive at port 31337
function traceTCPPacket(rawPacket){
    let host_ip = rawPacket.payload.saddr.addr.join('.');
    let host_port = rawPacket.payload.payload.sport;
    let host_mac = macAddressConverter(rawPacket.shost.addr);
    if(pendingSYNs[host_ip +':'+ host_port] != undefined){
        if(pendingSYNs[host_ip +':'+ host_port][0] !== host_mac) return;
        if(rawPacket.payload.payload.flags.rst){
            message = {
                message: `[?] Received RST from :${host_ip}: ${host_port}`,
                date: utilDate()
            }
            logger(message, 'debug')
        }else{
            message = {
                message: `[?] Received ACK from : ${host_ip}: ${host_port}`,
                date: utilDate()
            }
            logger(message, 'debug')
        }
        message = {
            message: ` [+] Validated : ${host_ip} is at ${pendingSYNs[host_ip +':'+ host_port][0]}`,
            date: utilDate()
        }
        logger(message, 'debug')
        validatedHosts[host_ip] = pendingSYNs[host_ip +':'+ host_port][0];
        fs.writeFileSync(location_db, JSON.stringify(validatedHosts));
        delete pendingSYNs[host_ip +':'+ host_port];
        //TODO: clear timeout on validation
    }
}

// ARP replies
function checkARPPackets(rawPacket){    
    let arpPacket = rawPacket.payload; //arp packet
    if(arpPacket.operation == 1) {
        return false
    }
    if(arpPacket.operation == 2){
        //exclude arp replies sent by itself
        if(macAddressConverter(rawPacket.shost.addr) === macAddressConverter(arpPacket.sender_ha.addr) && macAddressConverter(arpPacket.sender_ha.addr) === my_mac){
            return false
        }
    }
    
    return true
}

//validate source and destination mac address in mac header and arp header
function checkHeaders(rawPacket){
    let arpPacket = rawPacket.payload;

    //checking source mac address
    if(macAddressConverter(rawPacket.shost.addr) !==  macAddressConverter(arpPacket.sender_ha.addr)) {
        return false
    }
    //checking destination mac address
    let isMatching = macAddressConverter(rawPacket.dhost.addr) === 'ff:ff:ff:ff:ff:ff'
    isMatching = isMatching || (macAddressConverter(rawPacket.dhost.addr) == '00:00:00:00:00:00')
    isMatching = isMatching || (macAddressConverter(arpPacket.target_ha.addr) === 'ff:ff:ff:ff:ff:ff')
    isMatching = isMatching || (macAddressConverter(arpPacket.target_ha.addr) === '00:00:00:00:00:00')
    if(!isMatching){//not a matching reply
        if(macAddressConverter(rawPacket.dhost.addr) !== macAddressConverter(arpPacket.target_ha.addr)) {
            return false
        }
    }
    return true
}

//send a TCP SYN to the host and wait for 2 sec to receive a RST or ACK
function validateHost(host_ip, host_mac){
    message = {
        message: `[?] Validating : ${host_ip} is  at ${host_mac}`,
        date: utilDate()
    }
    logger(message, 'debug')
    if(validatedHosts[host_ip] != undefined){ //host is already validated
        if(validatedHosts[host_ip] === host_mac){//lets check current situation matches with validated one
            data = {
                message: `[+] Already Validated : ${host_ip} is  at ${validatedHosts[host_ip]}`,
                date: utilDate()
            }
            logger(message, 'debug')
        }else{
            data = {
                message: '[-] Validation Failed : '+host_ip+' at '+host_mac,
                date: utilDate()
            }
            logger(message)
        }
        return
    }
    //Host has not validated yet, let's do it
  var host_port = parseInt(Math.random()*(65535-1024) + 1024);
  var src_ip = ip.address();
  var src_mac = my_mac;
    if(!tcp.sendSYN(config.interface.name, src_mac, host_mac, src_ip, 31337, host_ip, host_port)){
        message = {
            message: `[?] Sent TCP SYN to : ${host_ip}:${host_port} at ${host_mac}`,
            date: utilDate()
        }
        logger(message, 'debug')
        
        pendingSYNs[host_ip +':'+ host_port] = [host_mac, Date.now()];
        setTimeout(handleTimedOutTCPSYNs, 2000, host_ip, host_port);
    }  
}

//No RST or ACK received for 2 sec
function handleTimedOutTCPSYNs(host_ip, host_port){
    if(pendingSYNs[host_ip + ':' + host_port] != undefined){//No RST or ACK received for this, most probably spoofing underway
        logger('[-] Validation Failed : '+host_ip+' at '+pendingSYNs[host_ip + ':' + host_port][0]);
        delete pendingSYNs[host_ip + ':' + host_port];
    }
}

function macAddressConverter(mac) {
    return mac.map(el => {
        let hexa = el.toString(16)
        if(hexa.length < 2) el = '0'+ hexa;
        else el = hexa;
        return el
    }).join(':')
}

const TIME_LIMIT = 1000*60*60;
const logCache = {};

function logger(str, type) {
    // const content = JSON.stringify(str);

    let time = new Date().getTime();
    
    if(type !== 'debug'){
        
        logging.info(str)
        fs.writeFileSync('./var/log/logArpSpoof.json', JSON.stringify(str));
        // fs.writeFile('./var/log/logArpSpoof.json', JSON.stringify(str, null, 4));
    }
}

module.exports = listenPacket

