# GuardianNet

GuardianNet, web tabanlı akıllı ağ güvenlik izleme ve aktif savunma sistemi için hazırlanmış bir Django MVP'sidir. Dashboard, cihazlar, uyarılar, güvenlik olayları, raporlar, honeypot görünümü ve ayarlar sayfalarını içerir.

## Kurulum

Komutları `manage.py` dosyasının bulunduğu dizinde çalıştırın:

```powershell
cd GuardianNet\GuardianNet
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r ..\..\requirements.txt
python manage.py migrate
python manage.py seed_demo_data
python manage.py createsuperuser
python manage.py runserver
```

Uygulama `http://127.0.0.1:8000/login/` adresinden açılır. Admin paneli `/admin/` altındadır.

## Demo Veri

```powershell
python manage.py seed_demo_data
```

Komut sabit demo kayıtlarını `update_or_create`/`get_or_create` ile hazırlar. Tekrar çalıştırılması kontrolsüz kopya üretmez. Kullanılan IP adresleri dokümantasyon için ayrılmış `192.0.2.0/24`, `198.51.100.0/24` ve `203.0.113.0/24` bloklarındandır.

## Kontrol ve Migration

```powershell
python manage.py check
python manage.py makemigrations
python manage.py migrate
python manage.py test
```

## Güvenlik Sınırları

- Sistem yalnızca savunma, tespit ve log analizi amacıyla geliştirilir.
- Yetkisiz ağ taraması yapmaz; MVP'deki ağ tarama düğmesi gerçek hedeflere paket göndermez ve demo veri üretir.
- Port tarama, SSH brute force ve ARP spoofing bileşenleri saldırı gerçekleştirmez; sağlanan gözlem/log kayıtlarındaki davranışları sınıflandırır.
- Exploit, malware, kimlik bilgisi hırsızlığı, persistence veya evasion kodu içermez.

## OpenCanary ve Harici Araçlar

OpenCanary opsiyoneldir. `opencanaryd` bulunursa arayüz kullanılabilir olduğunu gösterir; bulunmazsa honeypot sayfası demo/mock olaylarla çalışır. Scapy, Nmap ve Docker MVP için zorunlu değildir. Bu araçların yokluğu uygulamanın açılmasını engellemez.
