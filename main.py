import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from parsers import parse_ports
from scanner import tcp_syn_scan, udp_scan
from protocols import guess_protocol


def scan_port(ip, proto, port, args):
    is_open = False
    elapsed = 0.0

    if proto == 'tcp':
        is_open, elapsed = tcp_syn_scan(ip, port, args.timeout)
    elif proto == 'udp':
        is_open, elapsed = udp_scan(ip, port, args.timeout)

    if is_open:
        protocol_name = "-"
        if args.guess:
            protocol_name = guess_protocol(ip, port, proto, args.timeout)

        time_str = f"{elapsed:.1f}ms" if args.verbose else ""

        if args.verbose and args.guess:
            return f"{proto.upper()} {port}\t{time_str}\t{protocol_name}"
        elif args.verbose:
            return f"{proto.upper()} {port}\t{time_str}"
        elif args.guess:
            return f"{proto.upper()} {port}\t{protocol_name}"
        else:
            return f"{proto.upper()} {port}"
    return None


def main():
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("ip", help="IP адрес для сканирования")
    parser.add_argument("targets", nargs='+', help="Спецификации портов (tcp/80, udp/53)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Таймаут в секундах")
    parser.add_argument("-j", "--num-threads", type=int, default=50, help="Число потоков")
    parser.add_argument("-v", "--verbose", action="store_true", help="Подробный режим")
    parser.add_argument("-g", "--guess", action="store_true", help="Определение протокола")

    args = parser.parse_args()
    ip = args.ip

    ports_to_scan = []
    for target in args.targets:
        try:
            proto, ports = parse_ports(target)
            for p in ports:
                ports_to_scan.append((proto, p))
        except Exception as e:
            print(f"Ошибка в параметрах: {e}")
            sys.exit(1)

    with ThreadPoolExecutor(max_workers=args.num_threads) as executor:
        futures = {
            executor.submit(scan_port, ip, proto, port, args): (proto, port)
            for proto, port in ports_to_scan
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)


if __name__ == "__main__":
    main()