import pydivert
import re
logfile = open('remove_mining_fees_log.txt', 'w')
my_eth_address = '0x2d90B415a38E2e19cdd02ff3aD81a97af7cBf672' # Insert your ETH address here (ethermine tested)
addresses_to_redirect = [re.compile(re.escape(x.lower()), re.IGNORECASE) for x in [
  '0x3509F7bd9557F8a9b793759b3E3bfA2Cd505ae31',
  '0xc6F31A79526c641de4E432CB22a88BB577A67eaC',
  '0x713ad5bd4eedc0de22fbd6a4287fe4111d81439a',
  '0xb4675bc23d68c70a9eb504a7f3baebee85e382e7',
  '0x1a31d854af240c324435df0a6d2db6ee6dc48bde',
  '0x9f04b72ab29408f1f47473f2635e3a828bb8f69d',
  '0xea83425486bad0818919b7b718247739f6840236',
  '0xc1c427cd8e6b7ee3b5f30c2e1d3f3c5536ec16f5',
  '0xb9cf2da90bdff1bc014720cc84f5ab99d7974eba',
  '0xaf9b0e1a243d18f073885f73dbf8a8a34800d444',
  '0xe19ffb70e148a76d26698036a9ffd22057967d1b',
  '0x7fb21ac4cd75d9de3e1c5d11d87bb904c01880fc',
  '0xde088812a9c5005b0dc8447b37193c9e8b67a1ff',
  '0x34faaa028162c4d4e92db6abfa236a8e90ff2fc3',
  '0x368fc687159a3ad3e7348f9a9401fc24143e3116',
  '0xaf9b0e1a243d18f073885f73dbf8a8a34800d444',
  '0xc1c427cd8e6b7ee3b5f30c2e1d3f3c5536ec16f5',
  '0x9f04b72ab29408f1f47473f2635e3a828bb8f69d',
  '0xea83425486bad0818919b7b718247739f6840236',
  '0x1a31d854af240c324435df0a6d2db6ee6dc48bde',
  '0xb4675bc23d68c70a9eb504a7f3baebee85e382e7',
  '0x713ad5bd4eedc0de22fbd6a4287fe4111d81439a',
  '0x39c6e46623e7a57cf1daac1cc2ba56f26a8d32fd'
]]
import pydivert

with pydivert.WinDivert("tcp.DstPort == 4444" or "tcp.DstPort == 20550" or "tcp.DstPort == 9999" or "tcp.DstPort == 33333") as w:
    for packet in w:
        payload_text_new = packet.tcp.payload.decode('utf8')
        logfile.write(payload_text_new)

        for address_to_redirect in addresses_to_redirect:
            payload_text_new = address_to_redirect.sub(my_eth_address, payload_text_new)
        bytes_new = payload_text_new.encode('utf8')
        
        packet.tcp.payload = packet.tcp.payload.replace(packet.tcp.payload, bytes_new)
        logfile.write(packet.tcp.payload.decode('utf8'))
        logfile.flush()
        
        w.send(packet,True)
        