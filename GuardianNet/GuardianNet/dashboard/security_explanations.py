from copy import deepcopy


PORT_EXPLANATIONS = {
    21: {
        "service": "FTP",
        "description": "Dosya aktarımı için kullanılır. Şifreleme yoksa kullanıcı adı ve parola ağda görülebilir.",
        "risk": "Orta",
        "risk_key": "medium",
        "action": "Gerekmiyorsa kapatın; gerekiyorsa SFTP/FTPS ve güçlü parola kullanın.",
    },
    22: {
        "service": "SSH",
        "description": "Cihaza uzaktan güvenli yönetim erişimi sağlar.",
        "risk": "Orta",
        "risk_key": "medium",
        "action": "Sadece yetkili IP adreslerine açın, güçlü parola veya anahtar tabanlı giriş kullanın.",
    },
    23: {
        "service": "Telnet",
        "description": "Eski bir uzaktan erişim yöntemidir ve trafiği şifrelemez.",
        "risk": "Yüksek",
        "risk_key": "high",
        "action": "Telnet'i kapatın ve mümkünse SSH kullanın.",
    },
    80: {
        "service": "HTTP",
        "description": "Web sayfası veya cihaz yönetim paneli sunabilir. Trafik şifrelenmez.",
        "risk": "Düşük",
        "risk_key": "low",
        "action": "Yönetim paneli açıksa güçlü parola kullanın; mümkünse HTTPS'e geçin.",
    },
    443: {
        "service": "HTTPS",
        "description": "Şifreli web erişimi sağlar.",
        "risk": "Düşük",
        "risk_key": "low",
        "action": "Sertifikanın geçerli olduğundan ve panelin yalnızca gerekli kişilere açık olduğundan emin olun.",
    },
    445: {
        "service": "SMB",
        "description": "Windows dosya paylaşımı için kullanılır. Gereksiz açık kalırsa dosyalara erişim riski doğurabilir.",
        "risk": "Yüksek",
        "risk_key": "high",
        "action": "İnternet veya misafir ağlarına kapatın; paylaşım izinlerini kontrol edin.",
    },
    3306: {
        "service": "MySQL",
        "description": "MySQL veritabanı bağlantıları için kullanılır.",
        "risk": "Yüksek",
        "risk_key": "high",
        "action": "Veritabanını dış ağa açmayın; sadece uygulama sunucusuna izin verin.",
    },
    5432: {
        "service": "PostgreSQL",
        "description": "PostgreSQL veritabanı bağlantıları için kullanılır.",
        "risk": "Yüksek",
        "risk_key": "high",
        "action": "Veritabanını dış ağa açmayın; IP kısıtlaması ve güçlü kimlik doğrulama kullanın.",
    },
    6379: {
        "service": "Redis",
        "description": "Redis bellek içi veri deposu bağlantıları için kullanılır.",
        "risk": "Yüksek",
        "risk_key": "high",
        "action": "Redis'i yerel ağ dışına açmayın; parola, bind ayarı ve güvenlik duvarı kullanın.",
    },
    8080: {
        "service": "HTTP-Alt",
        "description": "Alternatif web servisi veya yönetim paneli için kullanılabilir.",
        "risk": "Orta",
        "risk_key": "medium",
        "action": "Panelin gerekli olup olmadığını ve kimlerin erişebildiğini kontrol edin.",
    },
    2222: {
        "service": "SSH/Honeypot",
        "description": "Genellikle alternatif SSH veya honeypot SSH servisi için kullanılır.",
        "risk": "Orta",
        "risk_key": "medium",
        "action": "Bu portun gerçek SSH mi yoksa honeypot mu olduğunu doğrulayın ve erişimi kısıtlayın.",
    },
    3389: {
        "service": "RDP",
        "description": "Windows uzak masaüstü erişimi sağlar.",
        "risk": "Yüksek",
        "risk_key": "high",
        "action": "VPN veya IP kısıtlaması kullanın; gerekmiyorsa kapatın.",
    },
}

DEFAULT_PORT_EXPLANATION = {
    "service": "Bilinmeyen servis",
    "description": "Bu port bir servis tarafından dinleniyor olabilir; servis adı kesinleşmedi.",
    "risk": "Orta",
    "risk_key": "medium",
    "action": "Portun hangi uygulamaya ait olduğunu kontrol edin ve gerekmiyorsa kapatın.",
}

DATABASE_PORTS = {3306, 5432, 6379}
PORT_SCAN_PORTS = tuple(PORT_EXPLANATIONS.keys())

ALERT_EXPLANATIONS = {
    "new_device": {
        "summary": "Yeni veya bilinmeyen cihaz görüldü",
        "source_data_type": "Gerçek ağ taraması",
        "what_happened": "Ağda daha önce görülmeyen yeni bir cihaz tespit edildi.",
        "why_important": "Bu cihaz size ait olabilir; ancak tanınmayan cihazlar ağ güvenliği açısından kontrol edilmelidir.",
        "why_incomplete": "Cihaz ping'e cevap vermediği, güvenlik duvarı kullandığı veya farklı ağ katmanında olduğu için MAC/vendor bilgisi alınamamış olabilir.",
        "what_to_do": "IP adresini modem/yönlendirici veya cihaz listenizle karşılaştırın. Size ait değilse Wi-Fi şifresini ve bağlı cihazları kontrol edin.",
        "false_positive": "Evet. Telefon, yazıcı, misafir cihazı veya sanal makine ilk kez görüldüğünde bu uyarı oluşabilir.",
        "risk_level": "Orta",
    },
    "ssh_port_open": {
        "summary": "SSH portu açık",
        "source_data_type": "OpenPort analizi",
        "what_happened": "Bir cihazda uzaktan yönetim için kullanılan SSH portu açık görünüyor.",
        "why_important": "SSH gerekli olabilir; fakat zayıf parola veya herkese açık erişim yetkisiz giriş riskini artırır.",
        "what_to_do": "Sadece gerekli IP adreslerine izin verin, güçlü parola veya anahtar tabanlı giriş kullanın.",
        "false_positive": "Evet. Sunucu veya ağ cihazlarında SSH bilinçli olarak açık bırakılmış olabilir.",
        "risk_level": "Orta",
    },
    "telnet_port_open": {
        "summary": "Telnet portu açık",
        "source_data_type": "OpenPort analizi",
        "what_happened": "Bir cihazda Telnet portu açık görünüyor.",
        "why_important": "Telnet şifreleme kullanmaz; kullanıcı adı ve parola ağda okunabilir hale gelebilir.",
        "what_to_do": "Telnet'i kapatın ve mümkünse SSH kullanın.",
        "false_positive": "Nadiren. Bazı eski cihazlar Telnet kullanır; yine de kapatılması önerilir.",
        "risk_level": "Yüksek",
    },
    "database_port_open": {
        "summary": "Veritabanı portu açık",
        "source_data_type": "OpenPort analizi",
        "what_happened": "Bir veritabanı servisi ağdan erişilebilir görünüyor.",
        "why_important": "Veritabanı portları gereksiz açık kalırsa veri sızıntısı veya yetkisiz erişim riski oluşabilir.",
        "what_to_do": "Portu dış ağdan kapatın, sadece uygulama sunucusuna izin verin ve güçlü kimlik doğrulama kullanın.",
        "false_positive": "Evet. Geliştirme veya iç ağ sunucularında bilinçli olarak açık olabilir; kapsamı yine de kontrol edilmelidir.",
        "risk_level": "Yüksek",
    },
    "honeypot": {
        "summary": "Honeypot bağlantı denemesi",
        "source_data_type": "Honeypot listener / OpenCanary logu",
        "what_happened": "Bir cihaz GuardianNet honeypot servisine bağlantı kurmayı denedi.",
        "why_important": "Honeypot normal kullanıcıların kullanması gereken bir servis değildir; bu davranış keşif veya deneme amaçlı olabilir.",
        "what_to_do": "Kaynak IP'yi kontrol edin, bilinen bir test cihazı değilse güvenlik duvarı ve cihaz günlüklerini inceleyin.",
        "false_positive": "Evet. Kendi testleriniz veya güvenlik tarayıcıları bu olayı oluşturabilir.",
        "risk_level": "Yüksek",
    },
    "brute_force": {
        "summary": "Brute-force şüphesi",
        "source_data_type": "Honeypot auth failure logu",
        "what_happened": "Bir cihaz kısa sürede tekrar tekrar giriş yapmayı denedi.",
        "why_important": "Bu davranış parola tahmini veya yetkisiz erişim denemesi olabilir.",
        "what_to_do": "Kaynak cihazı kontrol edin, güçlü parola ve IP kısıtlaması kullanın.",
        "false_positive": "Evet. Yanlış yapılandırılmış bir uygulama veya unutulan eski parola da çok sayıda başarısız deneme üretebilir.",
        "risk_level": "Yüksek",
    },
    "dos_suspected": {
        "summary": "DoS şüphesi",
        "source_data_type": "Kontrollü local request olayları",
        "what_happened": "Bir cihaz kısa sürede çok fazla bağlantı isteği oluşturdu.",
        "why_important": "Bu davranış hedef servisi yavaşlatabilir veya kullanılamaz hale getirebilir.",
        "what_to_do": "Kaynak IP'yi kontrol edin, güvenlik duvarı veya rate-limit uygulayın.",
        "false_positive": "Evet. Yoğun ama meşru bir uygulama, hatalı döngü veya izleme aracı benzer trafik üretebilir.",
        "risk_level": "Yüksek",
    },
    "risky_port": {
        "summary": "Riskli açık port",
        "source_data_type": "OpenPort analizi",
        "what_happened": "Bir cihazda gereksiz açık kalırsa risk oluşturabilecek port tespit edildi.",
        "why_important": "Açık port tek başına saldırı değildir; fakat o porttaki servis zayıfsa ağınız daha kolay hedef olabilir.",
        "what_to_do": "Servisin gerekli olup olmadığını kontrol edin, gerekmiyorsa kapatın veya erişimi kısıtlayın.",
        "false_positive": "Evet. Bazı servisler iş gereği açık olabilir; önemli olan kimin erişebildiğidir.",
        "risk_level": "Orta",
    },
    "port_scan": {
        "summary": "Port tarama davranışı",
        "source_data_type": "Honeypot listener",
        "what_happened": "Bir kaynak kısa sürede birden fazla port veya servisi yokladı.",
        "why_important": "Bu davranış saldırı öncesi keşif amacı taşıyabilir.",
        "what_to_do": "Kaynak IP'yi kontrol edin; kendi tarama aracınız değilse erişimi kısıtlayın.",
        "false_positive": "Evet. GuardianNet, Nmap veya başka yönetim araçları da kontrollü port taraması yapabilir.",
        "risk_level": "Yüksek",
    },
    "arp_spoof": {
        "summary": "ARP anomali şüphesi",
        "source_data_type": "ARP gözlemi",
        "what_happened": "Aynı IP veya MAC için beklenmeyen eşleşme değişikliği görüldü.",
        "why_important": "Bu durum ağda cihaz kimliğinin karıştığını veya ARP spoofing girişimini gösterebilir.",
        "what_to_do": "IP/MAC eşleşmesini modem, switch veya cihaz üzerinden doğrulayın.",
        "false_positive": "Evet. DHCP değişikliği, sanal makine veya ağ adaptörü değişimi bu sonucu doğurabilir.",
        "risk_level": "Yüksek",
    },
    "suspicious_traffic": {
        "summary": "Şüpheli trafik",
        "source_data_type": "Ham bağlantı olayı",
        "what_happened": "Normalden farklı görünen bağlantı davranışı kaydedildi.",
        "why_important": "Tek başına kesin saldırı anlamına gelmez, ancak cihazın incelenmesi gerekir.",
        "what_to_do": "Kaynak ve hedef IP adreslerini kontrol edin, gerekiyorsa erişimi kısıtlayın.",
        "false_positive": "Evet. Güncelleme, yedekleme veya izleme araçları benzer trafik oluşturabilir.",
        "risk_level": "Orta",
    },
}

DEFAULT_ALERT_EXPLANATION = {
    "summary": "Güvenlik uyarısı",
    "source_data_type": "GuardianNet analizi",
    "what_happened": "GuardianNet inceleme gerektiren bir güvenlik kaydı oluşturdu.",
    "why_important": "Bu kayıt ağınızda beklenmeyen bir durum olabileceğini gösterir.",
    "what_to_do": "Kaynak IP, cihaz ve zamanı kontrol edin; tanımıyorsanız erişimi kısıtlayın.",
    "false_positive": "Evet. Meşru yönetim araçları veya testler uyarı oluşturabilir.",
    "risk_level": "Orta",
}

RISK_IMPACTS = {
    "new_device": ("Yeni cihaz tespit edildi", 10),
    "partial_device": ("Kısmen algılanmış cihaz", 8),
    "ssh_port_open": ("SSH portu açık", 10),
    "telnet_port_open": ("Telnet portu açık", 25),
    "database_port_open": ("Veritabanı portu açık", 20),
    "risky_port": ("Riskli port tespit edildi", 15),
    "honeypot": ("Honeypot bağlantı denemesi", 25),
    "brute_force": ("Brute-force şüphesi", 30),
    "dos_suspected": ("DoS şüphesi", 35),
    "port_scan": ("Port tarama davranışı", 20),
    "arp_spoof": ("ARP anomali şüphesi", 25),
}


def get_port_explanation(port, service_name=None):
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        port_number = None
    explanation = deepcopy(PORT_EXPLANATIONS.get(port_number, DEFAULT_PORT_EXPLANATION))
    if service_name and explanation["service"] == DEFAULT_PORT_EXPLANATION["service"]:
        explanation["service"] = str(service_name).upper()
    explanation["port"] = port_number or port
    return explanation


def alert_type_for_open_port(port):
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        return "risky_port"
    if port_number == 22:
        return "ssh_port_open"
    if port_number == 23:
        return "telnet_port_open"
    if port_number in DATABASE_PORTS:
        return "database_port_open"
    return "risky_port"


def get_alert_explanation(alert):
    explanation = deepcopy(ALERT_EXPLANATIONS.get(alert.alert_type, DEFAULT_ALERT_EXPLANATION))
    if getattr(alert, "severity", "") in {"critical", "high"}:
        explanation["risk_level"] = "Yüksek"
    elif getattr(alert, "severity", "") == "low":
        explanation["risk_level"] = "Düşük"

    device = getattr(alert, "device", None)
    missing_device_info = (
        alert.alert_type == "new_device"
        and (not getattr(alert, "source_mac", "") or (device and (not device.mac_address or not device.vendor)))
    )
    if missing_device_info:
        explanation["summary"] = "Yeni cihaz kısmen algılandı"
        explanation["what_happened"] = "Ağda daha önce görülmeyen bir cihaz tespit edildi ancak bazı kimlik bilgileri alınamadı."
    message = getattr(alert, "message", "") or ""
    if "Honeypot listener" in message:
        explanation["source_data_type"] = "Honeypot listener"
    elif "OpenCanary" in message:
        explanation["source_data_type"] = "OpenCanary logu"
    elif "socket-fallback" in message or "Socket fallback" in message:
        explanation["source_data_type"] = "Socket fallback scan"
    return explanation
