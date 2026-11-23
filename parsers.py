def parse_ports(port_spec):
    parts = port_spec.split('/')
    proto = parts[0].lower()

    if proto not in ['tcp', 'udp']:
        raise ValueError(f"Неизвестный протокол: {proto}")

    ports = []
    if len(parts) == 1:
        ports = range(1, 65536)
    else:
        ranges = parts[1].split(',')
        for r in ranges:
            if '-' in r:
                start, end = map(int, r.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(r))

    return proto, ports