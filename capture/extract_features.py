import threading
import time
from pathlib import Path

from cicflowmeter.flow_session import FlowSession
from scapy.sendrecv import AsyncSniffer


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INPUT_FILE = PROJECT_ROOT / "data" / "live_demo.pcapng"
OUTPUT_FILE = PROJECT_ROOT / "data" / "live_flows.csv"


def start_periodic_gc(session, interval=1.0):
    stop_event = threading.Event()

    def gc_loop():
        while not stop_event.wait(interval):
            session.garbage_collect(time.time())

    thread = threading.Thread(target=gc_loop, name="flow-gc", daemon=True)
    thread.start()
    return stop_event, thread


print("Crunching PCAP into mathematical features...")
print(f"Input : {INPUT_FILE}")
print(f"Output: {OUTPUT_FILE}")

if not INPUT_FILE.exists():
    raise FileNotFoundError(f"PCAP file not found: {INPUT_FILE}")

session = FlowSession(output_mode="csv", output=str(OUTPUT_FILE))
gc_stop, gc_thread = start_periodic_gc(session)

# Do not pass a BPF filter here. On Windows, Scapy tries to use tcpdump to
# compile/apply offline filters, which raises: "tcpdump is not available".
sniffer = AsyncSniffer(
    offline=str(INPUT_FILE),
    prn=session.process,
    store=False,
)

try:
    sniffer.start()
    sniffer.join()
except KeyboardInterrupt:
    sniffer.stop()
finally:
    gc_stop.set()
    gc_thread.join(timeout=2.0)
    session.flush_flows()

print("Done! Saved as live_flows.csv")
