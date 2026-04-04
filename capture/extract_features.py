from cicflowmeter.sniffer import create_sniffer

print("Crunching PCAP into mathematical features...")

# Create the sniffer programmatically
sniffer, session = create_sniffer(
    input_file="../data/live_demo.pcapng",
    input_interface=None,
    output_mode="csv",
    output="../data/live_flows.csv"  
)

sniffer.start()
try:
    sniffer.join()
except KeyboardInterrupt:
    sniffer.stop()
    
print("Done! Saved as live_flows.csv")