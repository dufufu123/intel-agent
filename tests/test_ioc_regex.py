"""测试 IOC 正则提取"""
from intel_agent.tools.ioc_regex import (
    extract_all_ioc_candidates,
    extract_domain,
    extract_email,
    extract_hash,
    extract_ipv4,
    extract_url,
)


class TestIPv4Extraction:
    def test_extract_single_ip(self):
        results = extract_ipv4("连接至 192.168.1.100 的服务器")
        assert ("192.168.1.100", "IPv4") in results

    def test_extract_multiple_ips(self):
        text = "C2 服务器: 10.0.0.1, 45.33.32.156, 8.8.8.8"
        results = extract_ipv4(text)
        assert len(results) == 3

    def test_no_ip(self):
        results = extract_ipv4("没有 IP 地址的文本")
        assert len(results) == 0


class TestDomainExtraction:
    def test_extract_domain(self):
        results = extract_domain("恶意域名 evil.com 和 bad.org")
        domains = [r[0] for r in results]
        assert "evil.com" in domains
        assert "bad.org" in domains

    def test_subdomain(self):
        results = extract_domain("C2 位于 api.malware.evil.com")
        domains = [r[0] for r in results]
        assert "api.malware.evil.com" in domains


class TestHashExtraction:
    def test_md5(self):
        results = extract_hash("MD5: d41d8cd98f00b204e9800998ecf8427e")
        assert ("d41d8cd98f00b204e9800998ecf8427e", "MD5") in results

    def test_sha1(self):
        results = extract_hash("SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA1") in results

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        results = extract_hash(f"SHA256: {h}")
        assert (h, "SHA256") in results


class TestURLExtraction:
    def test_extract_url(self):
        results = extract_url("下载地址: https://evil.com/payload.exe")
        assert any("evil.com/payload.exe" in r[0] for r in results)


class TestEmailExtraction:
    def test_extract_email(self):
        results = extract_email("联系 phishing@evil.com 获取更多")
        assert ("phishing@evil.com", "Email") in results


class TestAllCandidates:
    def test_extract_all(self):
        text = """
        攻击者使用了 192.168.1.1 和 evil.com 作为 C2。
        下载地址: https://evil.com/malware.exe
        文件哈希: d41d8cd98f00b204e9800998ecf8427e
        联系邮箱: attacker@evil.com
        """
        results = extract_all_ioc_candidates(text)
        assert len(results) >= 5

    def test_deduplication(self):
        text = "evil.com 和 evil.com 和 evil.com"
        results = extract_all_ioc_candidates(text)
        domains = [r for r in results if r[0] == "evil.com"]
        assert len(domains) == 1

    def test_empty_text(self):
        results = extract_all_ioc_candidates("")
        assert len(results) == 0