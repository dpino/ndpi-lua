local ffi = require('ffi')
local C = ffi.C

local ndpi = ffi.load("ndpilua")
local pcap = ffi.load("pcap")

ffi.cdef([[
/* Pcap */
typedef struct pcap pcap_t;
struct pcap_pkthdr {
  uint64_t ts_sec;         /* timestamp seconds */
  uint64_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
};

int printf(const char *format, ...);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
void pcap_close(pcap_t *p);
const uint8_t *pcap_next(pcap_t *p, struct pcap_pkthdr *h);

/* NDPIReader */
typedef void (*callback)(int, const uint8_t *packet);

void addProtocolHandler(callback handler);
void init();
void setDatalinkType(pcap_t *handle);
void processPacket(const struct pcap_pkthdr *header, const uint8_t *packet);
void finish();

]])

local PROTOCOL = {
   DHCP = 18,
   DNS = 5,
   DropBox = 121,
   Google = 126,
   HTTP = 7,
   ICMP = 81,
   IMAPS = 51,
   NTP = 9,
   SSL = 91,
   Spotify = 156,
   Twitter = 120,
   YouTube = 124,
}

function onProtocol(id, packet)
   io.write("### ")
   if id == PROTOCOL.DHCP then
      print("DHCP")
   end
   if id == PROTOCOL.DNS then
      print("DNS")
   end
   if id == PROTOCOL.DropBox then
      print("DropBox")
   end
   if id == PROTOCOL.Google then
      print("Google")
   end
   if id == PROTOCOL.HTTP then
      print("HTTP")
   end
   if id == PROTOCOL.ICMP then
      print("ICMP")
   end
   if id == PROTOCOL.IMAPS then
      print("IMAPS")
   end
   if id == PROTOCOL.NTP then
      print("NTP")
   end
   if id == PROTOCOL.SSL then
      print("SSL")
   end
   if id == PROTOCOL.Spotify then
      print("Spotify")
   end
   if id == PROTOCOL.Twitter then
      print("Twitter")
   end
   if id == PROTOCOL.YouTube then
      print("YouTube")
   end
end

-- Register protocol handler
ndpi.addProtocolHandler(onProtocol)

local pcap = ffi.load("pcap")

local filename = "pcap/lamernews.pcap"
local fname = ffi.new("char[?]", #filename, filename)
local errbuf = ffi.new("char[512]")

-- Read pcap file
local handle = pcap.pcap_open_offline(fname, errbuf)
if handle == nil then
   C.printf(errbuf)
end

ndpi.init()
ndpi.setDatalinkType(handle)

local header = ffi.new("struct pcap_pkthdr")
-- Inspect each packet
local total_packets = 0
while (1) do
   local packet = pcap.pcap_next(handle, header)
   if packet == nil then break end
   ndpi.processPacket(header, packet)
   total_packets = total_packets + 1
end
pcap.pcap_close(handle)

-- Print results
ndpi.finish()

print("Total packets: "..total_packets)

