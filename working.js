const pcap = require('pcap')

let pcapSession = pcap.createSession('enp0s3', 'arp or (tcp dst port 31337)')
    
    pcapSession.on('packet', function (rawPacket) {
        let packet = pcap.decode.packet(rawPacket)
        console.log(JSON.stringify(rawPacket))
        // if(packet.payload.ethertype == 0x0800){//TCP
        //     console.log('TCP', JSON.stringify(packet.payload))            
        // }else if (packet.payload.ethertype == 0x0806){//ARP
        //     console.log('TCP', JSON.stringify(packet.payload))            
        // }        
    })





{"dhost":{"addr":[136,210,116,197,196,12]},"shost":{"addr":[8,0,39,228,127,250]},"ethertype":2048,"vlan":null,"payload":{"version":4,"headerLength":20,"diffserv":0,"length":52,"identification":38480,"flags":{"reserved":false,"doNotFragment":true,"moreFragments":false},"fragmentOffset":0,"ttl":64,"protocol":6,"headerChecksum":24819,"saddr":{"addr":[192,168,1,8]},"daddr":{"addr":[159,65,226,142]},"payload":{"sport":40432,"dport":80,"seqno":1408304676,"ackno":2694747392,"headerLength":32,"flags":{"nonce":false,"cwr":false,"ece":false,"urg":false,"ack":true,"psh":false,"rst":false,"syn":false,"fin":true},"windowSize":501,"checksum":17319,"urgentPointer":0,"options":{"mss":null,"window_scale":null,"sack_ok":null,"sack":null,"timestamp":4030379430,"echo":1431898014},"data":null,"dataLength":0}}}