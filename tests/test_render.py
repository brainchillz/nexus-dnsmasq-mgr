"""Pure render-function tests: stores in, dnsmasq config text out."""
import copy

from dnsmaqmgr import dnsmasq as dm
from dnsmaqmgr.core.store import DEFAULTS


def _settings(**kw):
    s = copy.deepcopy(DEFAULTS['settings'])
    s.update(kw)
    return s


def test_main_defaults():
    text = dm.render_main(_settings())
    assert 'port=0' not in text
    assert 'domain=lan' in text
    assert 'expand-hosts' in text
    assert 'server=1.1.1.1' in text
    assert 'no-resolv' in text
    assert 'cache-size=1000' in text
    assert 'dhcp-leasefile=' in text
    # No listen restrictions configured -> no loopback pin needed.
    assert 'listen-address=127.0.0.1' not in text


def test_main_dns_disabled():
    assert 'port=0' in dm.render_main(_settings(dns_enabled=False))


def test_main_interface_restriction_keeps_loopback():
    text = dm.render_main(_settings(interfaces=['eth0']))
    assert 'interface=eth0' in text
    assert 'listen-address=127.0.0.1' in text  # CHAOS stats need loopback


def test_main_dnssec_anchors():
    text = dm.render_main(_settings(dnssec=True))
    assert 'dnssec' in text
    assert text.count('trust-anchor=') == 2


def test_hosts_file_a_and_aaaa_and_disabled():
    dns = {'hosts': [
        {'id': 'h_1', 'name': 'nas.lan', 'a': '10.0.0.5', 'aaaa': 'fd00::5', 'enabled': True},
        {'id': 'h_2', 'name': 'off.lan', 'a': '10.0.0.6', 'aaaa': '', 'enabled': False},
    ]}
    text = dm.render_hosts(dns)
    assert '10.0.0.5 nas.lan' in text
    assert 'fd00::5 nas.lan' in text
    assert '# disabled: 10.0.0.6 off.lan' in text
    assert '\n10.0.0.6 off.lan' not in text


def test_dns_conf_records():
    dns = {'addresses': [{'domain': 'ads.com', 'ip': '0.0.0.0', 'enabled': True}],
           'cnames': [{'alias': 'www.lan', 'target': 'nas.lan', 'enabled': True}],
           'forwards': [{'domain': 'corp', 'upstream': '10.1.1.1', 'enabled': True}]}
    text = dm.render_dns(dns)
    assert 'address=/ads.com/0.0.0.0' in text
    assert 'cname=www.lan,nas.lan' in text
    assert 'server=/corp/10.1.1.1' in text
    assert 'addn-hosts=' in text


def test_dhcp_disabled_renders_nothing():
    dhcp = {'ranges': [{'start': '10.0.0.100', 'end': '10.0.0.199', 'tag': '',
                        'netmask': '', 'lease': '12h', 'enabled': True}]}
    text = dm.render_dhcp(dhcp, _settings(dhcp_enabled=False))
    assert 'dhcp-range' not in text
    assert 'aa:bb:cc:dd:ee:ff' not in dm.render_dhcp_hosts(
        {'static_leases': [{'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '1.2.3.4', 'enabled': True}]},
        _settings(dhcp_enabled=False))


def test_dhcp_range_forms():
    settings = _settings(dhcp_enabled=True)
    dhcp = {'ranges': [
        {'start': '10.0.0.100', 'end': '10.0.0.199', 'tag': 'lan', 'interface': '',
         'netmask': '255.255.255.0', 'lease': '12h', 'enabled': True},
        {'start': '10.1.0.10', 'end': '10.1.0.20', 'tag': '', 'interface': 'eth1',
         'netmask': '', 'lease': '1h', 'enabled': True},
        {'start': '10.2.0.10', 'end': '10.2.0.20', 'tag': '', 'interface': '',
         'netmask': '', 'lease': '1h', 'enabled': False},
    ]}
    text = dm.render_dhcp(dhcp, settings)
    assert 'dhcp-range=set:lan,10.0.0.100,10.0.0.199,255.255.255.0,12h' in text
    assert 'dhcp-range=interface:eth1,10.1.0.10,10.1.0.20,1h' in text
    assert '10.2.0.10' not in text  # disabled
    assert 'dhcp-authoritative' in text
    assert 'dhcp-hostsfile=' in text and 'dhcp-optsfile=' in text


def test_dhcp_hosts_and_opts_lines():
    settings = _settings(dhcp_enabled=True)
    dhcp = {'static_leases': [{'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '10.0.0.10',
                               'hostname': 'printer', 'tag': 'lan', 'enabled': True}],
            'options': [{'tag': 'lan', 'option': 'option:router', 'value': '10.0.0.1',
                         'enabled': True},
                        {'tag': '', 'option': '42', 'value': '10.0.0.9', 'enabled': True}]}
    hosts = dm.render_dhcp_hosts(dhcp, settings)
    opts = dm.render_dhcp_opts(dhcp, settings)
    assert 'aa:bb:cc:dd:ee:ff,set:lan,10.0.0.10,printer' in hosts
    assert 'tag:lan,option:router,10.0.0.1' in opts
    assert '42,10.0.0.9' in opts


def test_boot_arch_matching_and_proxy():
    settings = _settings(dhcp_enabled=True)
    nb = {'tftp_enabled': True, 'tftp_root': '/srv/tftp', 'tftp_secure': True,
          'proxy_dhcp': True, 'proxy_subnet': '10.0.0.0', 'pxe_prompt': 'Boot me',
          'entries': [{'id': 'b_1', 'name': 'UEFI x64', 'arches': ['7', '9'],
                       'filename': 'ipxe.efi', 'server': '10.0.0.5', 'enabled': True},
                      {'id': 'b_2', 'name': 'Any', 'arches': [],
                       'filename': 'undionly.kpxe', 'server': '', 'enabled': True}]}
    text = dm.render_boot(nb, settings)
    assert 'enable-tftp' in text
    assert 'tftp-root=/srv/tftp' in text
    assert 'tftp-secure' in text
    assert 'dhcp-match=set:b_1,option:client-arch,7' in text
    assert 'dhcp-match=set:b_1,option:client-arch,9' in text
    assert 'dhcp-boot=tag:b_1,ipxe.efi,,10.0.0.5' in text
    assert 'dhcp-boot=undionly.kpxe\n' in text
    assert 'dhcp-range=10.0.0.0,proxy' in text
    assert 'pxe-prompt="Boot me",3' in text
    assert 'pxe-service=BC_EFI,"UEFI x64",ipxe.efi' in text


def test_render_all_validates_with_real_dnsmasq():
    """The full default render must pass `dnsmasq --test`."""
    stores = {name: copy.deepcopy(DEFAULTS[name])
              for name in ('settings', 'dns', 'dhcp', 'netboot')}
    stores['settings']['dhcp_enabled'] = True
    stores['dhcp']['ranges'] = [{'start': '10.0.0.100', 'end': '10.0.0.199', 'tag': 'lan',
                                 'interface': '', 'netmask': '255.255.255.0',
                                 'lease': '12h', 'enabled': True}]
    rendered = dm.render_all(stores)
    ok, output = dm.validate_render(rendered)
    assert ok, output


def test_validate_catches_garbage():
    stores = {name: copy.deepcopy(DEFAULTS[name])
              for name in ('settings', 'dns', 'dhcp', 'netboot')}
    stores['settings']['extra_options'] = 'not-a-real-option=1'
    ok, output = dm.validate_render(dm.render_all(stores))
    assert not ok
    assert 'bad option' in output
