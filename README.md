# Haskell Nmap

## Usage

1. `nmap-probe scan 127.0.0.1/24`
Scans the IP range

2. `nmap-probe concat` or `nmap-probe cc`
Concatenates the results and prints them to stdout

3. `nmap-probe get 127.0.0.5`
Gets a specific host


Normally, I'll run `scan` on one window and then use `watch nmap-probe get <IP>` on another so I can watch the results come in real time.


## Installation

```
apt install nmap
git clone https://github.com/t94j0/haskell-nmap
cd haskell-nmap
stack install
(you may need to move the binary to a location the root user can access if you're not running in the root context)
mkdir /var/nmaplog
```
