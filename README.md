# Custom nmap-like TCP Port Scanner in C

A fast, multi-threaded TCP port scanner written in C that works on Linux, macOS, and Windows.

## Features

- **Fast multi-threaded scanning** - Scan 1-65535 ports quickly with configurable thread count
- **Cross-platform** - Works on Linux, macOS, and Windows
- **Service detection** - Identifies common services by port number
- **Configurable timeout** - Adjust connection timeout based on network speed
- **Simple CLI** - Easy-to-use command-line interface
- **No external dependencies** - Uses only standard C library and OS APIs

## Building

### Linux / macOS

```bash
cd nmap_c
make
```

### Windows

Using MinGW:
```bash
gcc -o nmap_c.exe main.c scanner.c -lws2_32
```

Or using MSVC:
```bash
cl main.c scanner.c ws2_32.lib
```

## Usage

### Basic scan (ports 1-1000)
```bash
./nmap_c google.com
```

### Scan specific port range
```bash
./nmap_c 192.168.1.1 -p 1-65535
```

### Custom thread count and timeout
```bash
./nmap_c example.com -p 1-10000 -t 128 -T 5
```

### Quiet mode with file output
```bash
./nmap_c localhost -p 80,443,443,22-25 -q -o report.txt
```

### Live progress while scanning
```bash
./nmap_c localhost -p 1-1000 -v
```

### JSON output
```bash
./nmap_c localhost -p 22-25 -j
```

### Help
```bash
./nmap_c -h
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p <start>[-<end>]` | Port range or comma-separated ports to scan | 1-1000 |
| `-t <threads>` | Number of scanning threads | 64 |
| `-T <timeout>` | Connection timeout (seconds) | 3 |
| `-q` | Quiet mode: suppress stdout banner and summary | - |
| `-v` | Show live progress updates while scanning | - |
| `-o <file>` | Write results to a file | - |
| `-j` | Output results as JSON | - |
| `-h` | Show help message | - |

## Output

The scanner displays:
- Port number
- Port status (OPEN, CLOSED, or FILTERED)
- Common service name (if known)

Example output:
```
Starting scan of google.com
Scanning ports 1-1000 with 64 threads (timeout: 3s)

============ SCAN RESULTS ============
Port    Status     Service
--------------------------------
80      OPEN       HTTP
443     OPEN       HTTPS

============ SUMMARY ============
Scan completed in 12 seconds
Open ports:     2
Closed ports:   996
Filtered ports: 2
Total scanned:  1000
```

## How It Works

1. **Non-blocking TCP connects** - Connects to ports without blocking
2. **Thread pool** - Distributes port scanning across multiple threads
3. **Socket select/poll** - Uses platform-specific I/O multiplexing (select on Windows/POSIX, kevent on macOS)
4. **Service lookup** - Maps ports to common services (SSH, HTTP, MySQL, etc.)

## Supported Services

The scanner recognizes these common services:
- FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53)
- HTTP (80), POP3 (110), IMAP (143), HTTPS (443), SMB (445)
- MySQL (3306), RDP (3389), PostgreSQL (5432)
- CouchDB (5984), Redis (6379), HTTP-Proxy (8080)
- MongoDB (27017), and others

## Performance Tips

- **Increase threads** for faster scanning: `./nmap_c target -t 256`
- **Adjust timeout** for slower networks: `./nmap_c target -T 10`
- **Reduce port range** to test quickly: `./nmap_c target -p 1-1024`

## Limitations

- TCP connect scanning only (no SYN scan, UDP, or ping)
- Basic service detection by port number only
- No OS fingerprinting or version detection
- Requires network access to target

## Examples

```bash
# Scan localhost for web services
./nmap_c localhost -p 80,443,8080,8443

# Deep scan with high thread count
./nmap_c 192.168.1.1 -p 1-65535 -t 256

# Quick scan with short timeout
./nmap_c example.com -p 1-1024 -T 1

# Scan specific service ports
./nmap_c target.com -p 20-25 -p 80 -p 443 -p 3306 -p 5432
```

## Troubleshooting

**"Connection refused" errors:**
- This is normal - it means the port is closed
- Filtered ports usually indicate a firewall

**Slow scanning:**
- Increase thread count: `-t 256`
- Reduce timeout: `-T 1`
- Use smaller port range

**"Permission denied" on Linux/macOS:**
- Not needed for TCP connect scanning
- If you need raw packet access (SYN scan), use sudo

## License

Free to use and modify for educational and personal use.

## Notes

This is an educational tool for network administration and security testing. Use responsibly and only on networks you own or have explicit permission to test.
