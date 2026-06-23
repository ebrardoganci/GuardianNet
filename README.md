# GuardianNet

GuardianNet, izinli yerel ağlarda cihaz keşfi, güvenlik log analizi ve honeypot gözlemi yapan Django tabanlı savunma projesidir. Exploit, port saldırısı veya parola denemesi gerçekleştirmez.

## Kurulum

Komutlar `manage.py` dosyasının bulunduğu dizinde çalıştırılır:

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

Arayüz: `http://127.0.0.1:8000/login/`

## Çalışma Modları

- **Real:** Yalnızca RFC1918 özel ağlarında (`10/8`, `172.16/12`, `192.168/16`) cihaz keşfi dener. Otomatik algılanan ağ `/24` ile sınırlandırılır. Public IP taranmaz ve port taraması yapılmaz.
- **Demo:** Dokümantasyon IP bloklarından sabit örnek kayıtlar kullanır.
- Gerçek keşif veya OpenCanary logu yoksa Django çalışmaya devam eder; real modda demo/fallback kayıt üretilmez.

`.env.example` desteklenen değişkenleri belgeler. Proje kökündeki `.env` otomatik yüklenir; `.env` dosyası kaynak kontrole eklenmemelidir. Aynı ayarlar web arayüzündeki Ayarlar sayfasından `SystemSetting` tablosuna da kaydedilebilir.

## Gerçek Cihaz Keşfi

Keşif sırası:

1. `psutil` aktif özel IPv4 arayüzünü ve subnet'i belirler.
2. Nmap varsa yalnızca host discovery için `nmap -sn` çalışır.
3. Nmap yoksa Scapy ile yerel ARP discovery denenir.
4. İkisi de kullanılamazsa hata `NetworkScan.notes` alanına yazılır; real modda demo/fallback cihaz üretilmez.

Manuel `LOCAL_SUBNET`, yalnızca sahibi olduğunuz veya açıkça izin verilmiş özel ağ olmalıdır. Varsayılan host limiti 1024'tür.

```powershell
python manage.py run_network_scan
```

### Windows'ta Nmap

Nmap'in resmi Windows kurucusunu kullanın, kurulum sırasında Npcap seçeneğini etkinleştirin ve yeni terminalde `nmap --version` ile doğrulayın. Scapy ARP keşfi de Npcap ve yönetici yetkisi gerektirebilir.

WSL/Ubuntu, OpenCanary ve Linux ağ araçları için daha sorunsuz bir ortamdır. WSL içindeki sanal ağın fiziksel LAN görünürlüğünün Windows yapılandırmasına bağlı olduğunu unutmayın.

## OpenCanary

Docker opsiyoneldir; Django Docker olmadan da çalışır. OpenCanary container'ı başlatmak için proje kökünde:

```powershell
docker compose --profile honeypot up --build -d
```

Örnek servisler host üzerinde `2121` (FTP), `2222` (SSH) ve `8080` (HTTP) portlarını kullanır. OpenCanary JSON lines log hedefi repo kökündeki `logs/opencanary.log` dosyasıdır. `.env` içinde aynı dosyayı gösterin:

```env
OPENCANARY_LOG_PATH=logs/opencanary.log
ENABLE_HONEYPOT_LOGS=True
```

Logları Django veritabanına aktarmak için `manage.py` dizininde çalıştırın:

```powershell
python manage.py ingest_honeypot_logs
```

Komut kaç satır okunduğunu, kaç gerçek event eklendiğini, kaç duplicate atlandığını ve kaç parse hatası olduğunu raporlar. Log dosyası yoksa hata koduyla çıkmaz; dashboard Honeypot sayfasında “OpenCanary logu bulunamadı” görünür. Log dosyası var ama gerçek event yoksa “Henüz gerçek honeypot olayı yok” boş durumu gösterilir.

Güvenli parser testi için otomatik kullanılmayan örnek dosya vardır:

```powershell
python manage.py ingest_honeypot_logs --path ..\..\logs\opencanary.sample.jsonl
```

Bu örnek gerçek OpenCanary yerine geçmez ve dashboard real modda kendiliğinden fake veri üretmez.

## Savunma Analizi

```powershell
python manage.py ingest_honeypot_logs
python manage.py analyze_security
```

İlk komut OpenCanary loglarını aktarır ve port/servis çeşitliliği ile başarısız SSH kayıtlarını analiz eder. İkinci komut ARP eşleşme anomalisi, port tarama şüphesi ve kaba kuvvet şüphesi kontrollerini çalıştırıp risk snapshot'ı üretir.

Risk puanı aktif uyarı, yüksek/kritik önem, güvenilmeyen cihaz, gerçek honeypot olayı ve son 24 saatteki savunma tespitlerine göre hesaplanır. `security_score = 100 - risk_score` olarak tutulur.

## Test

```powershell
python manage.py check
python manage.py test
python manage.py makemigrations
python manage.py migrate
python manage.py run_network_scan
python manage.py ingest_honeypot_logs
python manage.py analyze_security
```

Bu sistem yalnızca kullanıcının kendi yerel ağı veya açıkça izin verilmiş test ağlarında kullanılmalıdır.
