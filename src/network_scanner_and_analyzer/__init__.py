"""Command line entry point."""
import argparse
import logging
from pathlib import Path
from queue import Queue, Full
import sys

from config.settings import Settings
from src.capture import CaptureProducer, packet_to_record
from src.database import BatchWorker, JsonSink, PostgresSink
from src.detector import Detector


def nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description="Capture or replay IP packets and detect suspicious patterns.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pcap", type=Path, help="Read an existing PCAP/PCAPNG file")
    source.add_argument("--interface", help="Live capture interface")
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--filter", help="Live capture BPF filter (requires libpcap/Npcap)")
    parser.add_argument("--count", type=nonnegative_int, default=0, help="Maximum captured packets; 0 means unlimited")
    parser.add_argument("--duration", type=nonnegative_int, default=0, help="Live capture seconds; 0 means unlimited")
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--output", type=Path, help="Write JSON lines to a file (default: stdout)")
    parser.add_argument("--postgres", action="store_true", help="Store using DATABASE_URL")
    parser.add_argument("--init-db", action="store_true", help="Create database tables and exit")
    args = parser.parse_args(argv)
    if args.output and (args.postgres or args.init_db):
        parser.error("--output cannot be combined with --postgres or --init-db")
    if args.pcap and (args.filter or args.duration):
        parser.error("--filter and --duration apply only to live capture")
    if args.output and args.pcap and args.output.resolve() == args.pcap.resolve():
        parser.error("Output must not overwrite the input capture")
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    sink = stream = worker = sniffer = None
    try:
        from scapy.all import AsyncSniffer, PcapReader, get_if_list
        if args.list_interfaces:
            print("\n".join(get_if_list()))
            return 0
        settings = Settings.from_env()
        detector = Detector.from_yaml(args.rules)
        if args.postgres or args.init_db:
            if not settings.database_url:
                parser.error("DATABASE_URL is required for PostgreSQL")
            sink = PostgresSink(settings.database_url)
            if args.init_db:
                sink.initialize()
                return 0
        else:
            stream = args.output.open("w", encoding="utf-8") if args.output else sys.stdout
            sink = JsonSink(stream)
        queue = Queue(maxsize=settings.queue_size)
        producer = CaptureProducer(queue, settings.payload_limit)
        worker = BatchWorker(queue, detector, sink, settings.batch_size, settings.flush_interval)
        worker.start()
        try:
            if args.pcap:
                with PcapReader(str(args.pcap)) as reader:
                    for index, packet in enumerate(reader, 1):
                        if worker.failed.is_set():
                            break
                        record = packet_to_record(packet, settings.payload_limit)
                        if record is not None:
                            while not worker.failed.is_set():
                                try:
                                    queue.put(record, timeout=0.1)
                                    producer.accepted += 1
                                    break
                                except Full:
                                    pass
                        else:
                            producer.ignored += 1
                        if args.count and index >= args.count:
                            break
            else:
                sniffer = AsyncSniffer(iface=args.interface or settings.interface, filter=args.filter,
                                       prn=producer, store=False, count=args.count,
                                       timeout=args.duration or None)
                sniffer.start()
                while sniffer.thread.is_alive() and not worker.failed.wait(0.1):
                    pass
                if not sniffer.thread.is_alive():
                    sniffer.join()  # Re-raise capture startup/runtime errors.
        except KeyboardInterrupt:
            logging.info("Stopping capture and flushing queued packets")
        finally:
            try:
                if sniffer and sniffer.running:
                    sniffer.stop()
            finally:
                worker.stopping.set()
                worker.join()
        if worker.error:
            raise RuntimeError("Storage worker failed; some accepted packets were not saved") from worker.error
        logging.info("Saved %d packets; %d alerts; %d dropped; %d ignored; %d malformed",
                     worker.written, worker.alert_count, producer.dropped, producer.ignored, producer.malformed)
        return 0
    except Exception as error:
        logging.error("%s: %s", type(error).__name__, error)
        return 1
    finally:
        if sink:
            sink.close()
        if stream is not None and stream is not sys.stdout:
            stream.close()
