// Use require('arpjs') if youre running this example elsewhere.
var arp = require('arpjs')
arp.setInterface('enp0s3');
arp.send({
  'op': 'request',
  'src_ip': '192.168.1.5',
  'dst_ip': '192.168.1.9',
  'src_mac': '8f:3f:20:33:54:44',
  'dst_mac': 'ff:ff:ff:ff:ff:11'
})


arp.poison('192.168.1.11', '192.168.1.12')