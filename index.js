var util          = require('util'),

    ARP_Discovery = require('./arp-discovery')
  ;

  var arp = new ARP_Discovery({timeout:1000, flood_interval: 300, resolve_macvendor:true});

  arp.on('error', function(err){
    console.log(err);
  });

  // Discovery :
  arp.on('success', function(res) {
      if (!res) {
          console.log('!res');
          return;
      }
      console.log('success: '+util.inspect(res, { depth: null }));
      console.log('getMacs: '+util.inspect(arp.getMacs(), { depth: null }));
      console.log('getIps:  '+util.inspect(arp.getIps(), { depth: null }));
  });
  arp.discover();

  // Monitoring :
  arp.on('lost', function(lost){
    console.log('lost: '+util.inspect(lost, { depth: null }));
  });

  arp.on('found', function(found){
    console.log('found: '+util.inspect(found, { depth: null }));
  });

  arp.on('update', function(update){
    console.log('update: '+util.inspect(update, { depth: null }));
  });

  // Monitoring interval (ms)
  arp.monitor(40000);