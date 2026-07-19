# cabotisocks

[![Build](https://github.com/windowsair/cabotisocks/actions/workflows/build.yml/badge.svg)](https://github.com/windowsair/cabotisocks/actions/workflows/build.yml)

Yet another eBPF-based transparent proxy for Linux.

## Features

- [x] Support for UDP/TCP
- [x] Support for SOCKS5 server
- [x] cgroup-based policy control

## Benchmark

See [benchmark](https://github.com/windowsair/cabotisocks-benchmark.git)

![upload](https://github.com/windowsair/cabotisocks-benchmark/raw/master/upload.png)
![download](https://github.com/windowsair/cabotisocks-benchmark/raw/master/download.png)

## Getting Started

1. Download from [releases page](https://github.com/windowsair/cabotisocks/releases)

2. Create a `config.json` (see [Configuration](#configuration) below, or copy `config/config.example.json`).

3. Run as root (eBPF requires `CAP_BPF` and `CAP_NET_ADMIN`):

    ```bash
    sudo ./cabotisocks ./config.json
    ```

4. Run your target application inside a monitored cgroup:

    ```bash
    # In this case, we use "cabotisocks" as cgroup path
    sudo mkdir -p /sys/fs/cgroup/cabotisocks
    sudo sh -c "echo $$ > /sys/fs/cgroup/cabotisocks/cgroup.procs"
    # Subsequent commands in this shell will be proxied.
    ```

    For most Linux distributions, user programs run under the cgroup `/user.slice/`, so you can set `include_path` to `/user.slice/` without any additional cgroup configuration.

    For global proxying, set `include_path` to `/` and use `exclude_path` to skip specific cgroups, such as the one where the SOCKS5 server application resides.

> See the [Arch Linux cgroups wiki](https://wiki.archlinux.org/title/Cgroups) for more ways to launch processes within specific cgroups.

## Configuration

**Quick Start**:

```json
{
  "version": "1",
  "server": {
    "type": "socks5",
    "host": "127.0.0.1",
    "port": 10808,
    "username": "",
    "password": ""
  },
  "misc": {
    "enable_udp": true
  },
  "cgroup": {
    "include_path": "/user.slice/",
    "exclude_path": "/system.slice/"
  },
  "rules": [
    {
      "name": "Bypass local",
      "host": [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3"
      ],
      "action": "direct"
    },
    {
      "name": "proxy",
      "action": "proxy"
    }
  ]
}
```

### server

| Field      | Type   | Required | Description                         |
|------------|--------|----------|-------------------------------------|
| `type`     | string | yes      | Must be `"socks5"`                  |
| `host`     | string | yes      | SOCKS5 server address               |
| `port`     | int    | yes      | SOCKS5 server port                  |
| `username` | string | no       | SOCKS5 username (empty for no auth) |
| `password` | string | no       | SOCKS5 password (empty for no auth) |

### cgroup

| Field          | Type   | Required | Description                                          |
|----------------|--------|----------|------------------------------------------------------|
| `include_path` | string | yes      | Cgroup path to monitor (e.g. `"/cabotisocks"`, `"/"`) |
| `exclude_path` | string | no       | Cgroup path to bypass (e.g. `"/system.slice/"`)       |

### misc

| Field       | Type    | Default | Description              |
|-------------|---------|---------|--------------------------|
| `enable_udp`| boolean | `false`  | Enable UDP proxying     |

### rules

| Field     | Type            | Required | Description                           |
|-----------|-----------------|----------|---------------------------------------|
| `name`    | string          | no       | Human-readable name for the rule      |
| `action`  | string          | yes      | `"proxy"`, `"direct"`, or `"block"`   |
| `host`    | array of CIDRs  | no       | Match by destination IP               |
| `port`    | int             | no       | Match by destination port             |
| `process` | string          | no       | Match by process name prefix          |

## Build from Source

```bash
git clone https://github.com/windowsair/cabotisocks.git
cd cabotisocks
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The binary will be available at `build/cabotisocks`.

## Roadmap

- [ ] Full cone NAT support
- [ ] IPv6 support

## License

[GPLv2 or later](./LICENSE)
