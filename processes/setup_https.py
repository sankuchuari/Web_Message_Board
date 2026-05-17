import socket
import datetime
import os
import ipaddress


def get_ip_addresses():
    """获取本机所有的有效 IPv4 和 IPv6 地址"""
    ips = []
    try:
        hostname = socket.gethostname()
        # 仅捕获 socket 相关的具体异常
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip = item[4][0]
            if ip.startswith("127.") or ip == "::1" or ip.startswith("fe80"):
                continue
            ips.append(ip)
    except (socket.gaierror, socket.error) as e:
        print(f"主机名解析警告: {e}")

    # 尝试通过 UDP 联通获取主要出口 IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2.0)
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
    except (socket.error, OSError):
        # 如果没有网络连接或权限受限，忽略此步骤
        pass

    return list(set(ips))

def generate_ssl_files():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    print("正在检测网络环境...")
    ips = get_ip_addresses()

    # 生成 RSA 私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 构建 SAN 列表
    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]

    print("检测到以下 IP 地址并将其加入证书:")
    for ip in ips:
        print(f" - {ip}")
        try:
            san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            continue

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Rust Actix Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, ips[0] if ips else "localhost"),
    ])

    # 使用 Python 3.12+ 推荐的时区感知 UTC 时间
    now = datetime.datetime.now(datetime.UTC)
    expiry = now + datetime.timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expiry)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # 导出私钥 (不加密)
    with open("./static/key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 导出证书
    with open("./static/cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("\n" + "="*40)
    print("✅ 成功生成证书文件！")
    print(f"📁 运行目录: {os.getcwd()}")
    print(f"⏳ 有效期至: {expiry.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("="*40)

if __name__ == "__main__":
    generate_ssl_files()