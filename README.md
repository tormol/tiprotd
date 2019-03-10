# tiprotd

An implementation of multiple trivial and abadoned network protocols, with a twist.
It is written in Rust, using the low-level async library `mio`.

## Implemented protocols

* echo (TCP and UDP port 7)
* discard (TCP and UDP port 9)
* QOTD (TCP and UDP port 17)
* time (TCP and UDP port 37)

To prevent being used for UDP amplification DDoS attacks, UDP replies are
limited to 1 MiB per IPv4 address or IPv6 /64 network within a 10 minute window.

I plan to also implement at least daytime (port 13) and TCPMUX (port 1),
and want to also support the transport layer protocols SCTP, DCCP and UDPlite
as well as unix domain sockets (including SOCK_SEQPACKET)

## Invocation

It currently doesn't support any configuration and ignore command line arguments.

If binding to the first port fails due to permission error, it will add 10000 to
the port numbers and try again. (so echo becomes port 10007 and time becomes port
10037)
It does not drop root privileges after setting up the listening sockets, so for
security it should be given the CAP_NET_BIND_SERVICE capability and then run as
a normal user:

```sh
cargo build --release
sudo setcap CAP_NET_BIND_SERVICE=+eip target/release/tiprotd
sudo -u nobody target/release/tiprotd
```

## Clients

For most protocols, netcat or socat is all you need;
For example use `nc -u localhost 10007` for UDP echo running on an unprivileged port or
`socat - TCP6:[::1]:10017` for TCP QOTD.

Tip: to make netcat terminate after receiving the TCP response, pass it the `-N` flag and redirect stdin to /dev/null: `nc -N 127.0.0.1 10017 </dev/null`

In clients/ there is a client that decodes the response from the binary *time* protocol.

To find the listening sockets, (on Linux) run `ss --listening --query inet --numeric  -processes` or `sudo netstat --listening --numeric-ports --inet --inet6 --programs`.

## License

Copyright 2019 Torbjørn Birch Moltu

This program can be redistributed and/or modified under the terms of the
GNU Affero General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see https://www.gnu.org/licenses/

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, shall be licensed as above,
without any additional terms or conditions.
