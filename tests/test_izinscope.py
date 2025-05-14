# tests/test_izinscope.py
import pytest
import ipaddress
import socket
import dns.resolver
from izinscope import log, resolve_domain, load_scope, is_ip_in_scope, single_check, write_output

class DummyAnswer:
    def __init__(self, text):
        self._text = text
    def to_text(self):
        return self._text

class DummyResolver:
    def __init__(self, records):
        self._records = records
    def resolve(self, domain, record):
        if domain in self._records and record in self._records[domain]:
            return [DummyAnswer(ip) for ip in self._records[domain][record]]
        else:
            raise dns.resolver.NoAnswer()


def test_resolve_domain(monkeypatch):
    records = {'example.com': {'A': ['1.2.3.4'], 'AAAA': ['::1']}}
    resolver = DummyResolver(records)
    domain, ips = resolve_domain('example.com', resolver)
    assert domain == 'example.com'
    assert set(ips) == {'1.2.3.4', '::1'}


def test_load_scope(tmp_path, monkeypatch):
    # Préparer un fichier scope.txt
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("192.168.0.0/24\nexample.com\n")
    # Simuler la résolution DNS pour example.com
    monkeypatch.setattr(socket, 'gethostbyname_ex', lambda name: (name, [], ['5.6.7.8']))
    networks, ips = load_scope(str(scope_file))
    assert ipaddress.ip_network("192.168.0.0/24") in networks
    assert "5.6.7.8" in ips


def test_is_ip_in_scope():
    networks = [ipaddress.ip_network("10.0.0.0/8")]
    ips = {"1.2.3.4"}
    assert is_ip_in_scope("10.1.2.3", networks, ips)
    assert is_ip_in_scope("1.2.3.4", networks, ips)
    assert not is_ip_in_scope("8.8.8.8", networks, ips)


def test_single_check_domain_in_scope(monkeypatch, capsys):
    networks = [ipaddress.ip_network("8.8.8.0/24")]
    ips = {"8.8.8.8"}
    monkeypatch.setattr(socket, 'gethostbyname_ex', lambda name: (name, [], ['8.8.8.8']))
    single_check("example.com", networks, ips)
    captured = capsys.readouterr()
    assert "[+]" in captured.out
    assert "example.com résout vers:" in captured.out


def test_single_check_ip_not_in_scope(capsys):
    networks = []
    ips = set()
    single_check("9.9.9.9", networks, ips)
    captured = capsys.readouterr()
    assert "[-]" in captured.out


def test_single_check_invalid_target(capsys):
    # Cible ni domaine ni IP valide
    with pytest.raises(SystemExit):
        single_check("not_valid", [], set())
    captured = capsys.readouterr()
    assert "Ni un domaine valide ni une IP valide" in captured.out


def test_write_output(tmp_path):
    data = {"a.com": ["1.2.3.4", "5.6.7.8"]}
    txt_file = tmp_path / "out.txt"
    write_output(str(txt_file), data, csv=False)
    assert txt_file.read_text().splitlines() == ["a.com"]
    csv_file = tmp_path / "out.csv"
    write_output(str(csv_file), data, csv=True)
    assert csv_file.read_text().splitlines() == ["a.com,1.2.3.4,5.6.7.8"]
