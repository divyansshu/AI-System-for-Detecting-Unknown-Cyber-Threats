from cicflowmeter.sniffer import create_sniffer

print("📡 Crunching PCAP into mathematical features...")

# Create the sniffer programmatically
sniffer, session = create_sniffer(
    input_file="live_demo.pcapng",
    input_interface=None,
    output_mode="csv",
    output="live_flows.csv"  # <--- Change this from 'output_file' to just 'output'
)

sniffer.start()
try:
    sniffer.join()
except KeyboardInterrupt:
    sniffer.stop()
    
print("✅ Done! Saved as live_flows.csv")