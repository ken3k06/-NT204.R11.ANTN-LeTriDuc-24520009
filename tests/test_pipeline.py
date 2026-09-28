from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw

from src.models.event import AppProtocol, Transport
from src.pipeline import process


def _event(pkt, packet_id=1):
    return process(bytes(pkt[IP]), timestamp=1700000000.0, packet_id=packet_id)


def test_tcp_syn_flag():
    event = _event(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))

    assert event.transport == Transport.TCP
    assert event.tcp_flags["SYN"] == 1
    assert event.tcp_flags["ACK"] == 0


def test_tcp_syn_ack_flag():
    event = _event(IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, flags="SA"))

    assert event.tcp_flags["SYN"] == 1
    assert event.tcp_flags["ACK"] == 1


def test_udp_packet():
    event = _event(IP() / UDP(sport=1111, dport=2222) / Raw(b"hello"))

    assert event.transport == Transport.UDP
    assert event.payload_len == 5
    assert event.udp_len is not None


def test_http_get():
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    event = _event(IP() / TCP(sport=1234, dport=8080, flags="PA") / Raw(payload))

    assert event.app_protocol == AppProtocol.HTTP
    assert event.app_data["method"] == "GET"
    assert event.app_data["path"] == "/index.html"


def test_http_post_body():
    payload = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=a"
    event = _event(IP() / TCP(sport=1234, dport=80, flags="PA") / Raw(payload))

    assert event.app_protocol == AppProtocol.HTTP
    assert event.app_data["method"] == "POST"
    assert event.app_data["body_len"] == 6


def test_http_response():
    payload = b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\nhello"
    event = _event(IP() / TCP(sport=80, dport=1234, flags="PA") / Raw(payload))

    assert event.app_protocol == AppProtocol.HTTP
    assert event.app_data["status_code"] == 200


def test_dns_query():
    event = _event(IP() / UDP(sport=4444, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))

    assert event.app_protocol == AppProtocol.DNS
    assert event.app_data["questions"][0]["name"] == "example.com."


def test_dns_response():
    dns = DNS(
        id=1,
        qr=1,
        qd=DNSQR(qname="example.com"),
        an=DNSRR(rrname="example.com", rdata="1.2.3.4"),
    )
    event = _event(IP() / UDP(sport=53, dport=4444) / dns)

    assert event.app_protocol == AppProtocol.DNS
    assert event.app_data["answers"][0]["data"] == "1.2.3.4"


def test_smtp_command():
    event = _event(IP() / TCP(sport=1234, dport=25, flags="PA") / Raw(b"HELO mail.local\r\n"))

    assert event.app_protocol == AppProtocol.SMTP
    assert event.app_data["command"] == "HELO"


def test_smtp_response():
    event = _event(IP() / TCP(sport=25, dport=1234, flags="PA") / Raw(b"250 OK\r\n"))

    assert event.app_protocol == AppProtocol.SMTP
    assert event.app_data["status_code"] == 250


def test_unknown_protocol():
    event = _event(IP(proto=1) / Raw(b"abc"))

    assert event.transport == Transport.UNKNOWN
    assert event.error is None


def test_malformed_packet():
    event = process(b"\x45\x00", timestamp=1700000000.0, packet_id=1)

    assert event.is_error
