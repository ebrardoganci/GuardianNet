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

Docker opsiyoneldir; Django Docker olmadan da çalışır. OpenCanary container'ı başlatmak için Docker Desktop çalışır durumdayken proje kökünde:

```powershell
docker compose up --build -d
docker compose ps
docker compose logs --tail=100
```

Container'ı durdurmak için:

```powershell
docker compose down
```

Örnek servisler host üzerinde yalnızca lokal geliştirme için `2121` (FTP), `2222` (SSH) ve `8080` (HTTP) portlarını kullanır. Bu portlardan biri doluysa `.env` içinde `OPENCANARY_FTP_PORT`, `OPENCANARY_SSH_PORT` veya `OPENCANARY_HTTP_PORT` değerini değiştirin; container iç portları aynı kalır. OpenCanary JSON lines log hedefi repo kökündeki `logs/opencanary.log` dosyasıdır. Compose mount'u `./logs:/var/tmp/opencanary` şeklindedir ve container içindeki `/var/tmp/opencanary/opencanary.log` dosyası Django tarafından `.env` içindeki göreli path ile okunur:

```env
OPENCANARY_LOG_PATH=logs/opencanary.log
ENABLE_HONEYPOT_LOGS=True
# Opsiyonel host port degisiklikleri:
OPENCANARY_FTP_PORT=2121
OPENCANARY_SSH_PORT=2222
OPENCANARY_HTTP_PORT=8080
```

Logları Django veritabanına aktarmak için `manage.py` dizininde çalıştırın:

```powershell
python manage.py ingest_honeypot_logs
```

Komut kaç satır okunduğunu, kaç gerçek event eklendiğini, kaç duplicate atlandığını, kaç non-event satırın yok sayıldığını ve kaç parse hatası olduğunu raporlar. OpenCanary'nin `Canary running` veya servis başlatma gibi lifecycle JSON satırları gerçek honeypot eventi sayılmaz ve `ignored` olarak raporlanır. Log dosyası yoksa hata koduyla çıkmaz; dashboard Honeypot sayfasında “OpenCanary logu bulunamadı” görünür. Log dosyası var ama gerçek event yoksa “Henüz gerçek honeypot olayı yok” boş durumu gösterilir.

Health check için:

```powershell
python manage.py check_runtime_health
```

OpenCanary container başladıktan sonra `logs/opencanary.log` oluşmalı ve health check'te OpenCanary log dosyası OK görünmelidir. Dosya yoksa bu hata değil warning olarak kalır; Django fake/demo honeypot event üretmez. Windows'ta Docker Desktop'ın Linux engine'i açık olmalı ve repo klasörü volume sharing erişimine sahip olmalıdır; OneDrive altındaki repo yollarında Docker dosya paylaşım izinlerini ayrıca kontrol etmek gerekebilir.

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

## Monitoring Cycle

Gerçek kullanımda ağ keşfi, OpenCanary log aktarımı ve risk analizini tek komutla çalıştırabilirsiniz:

```powershell
python manage.py run_monitoring_cycle
python manage.py run_monitoring_cycle --scan-limit 10
python manage.py run_monitoring_cycle --skip-honeypot
```

Dashboard ana sayfasındaki **Monitoring Cycle Çalıştır** butonu da aynı servis akışını POST ile çalıştırır. Formdaki scan limit alanı cihaz sayısını sabitlemez; yalnızca taranacak host hedeflerini sınırlar. Varsayılan değer `.env` içindeki `MONITORING_CYCLE_SCAN_LIMIT` ile değiştirilebilir.

`--scan-limit` cihaz sayısını sabitlemez; yalnızca taranacak host hedeflerini sınırlar. Gerektiğinde `--skip-scan`, `--skip-honeypot` veya `--skip-analysis` ile bir adımı atlayabilirsiniz. Windows'ta gerçek ağ keşfi için Nmap ve Npcap kurulu olmalı; yoksa Scapy ARP keşfi denenir ve o da çalışmazsa real modda demo/fallback veri üretilmez.

Her çalıştırma `MonitoringCycleRun` olarak kaydedilir. Dashboard ana sayfasındaki **Son Monitoring Cycle** paneli son çalışma zamanını, scan/honeypot/analiz özetini, ignored/parse error sayılarını ve varsa hata özetini gösterir. Dashboard sayfası 60 saniyede bir otomatik yenilenir ve üst bölümde son render zamanı görünür. Periyodik kullanım için Windows Task Scheduler veya Linux/macOS cron ile aynı `python manage.py run_monitoring_cycle --scan-limit 10` komutu zamanlanabilir.

## Runtime / Sistem Sağlığı

Gerçek modun hazır olup olmadığını tek yerden görmek için:

```powershell
python manage.py check_runtime_health
```

Komut `GUARDIANNET_MODE`, `LOCAL_SUBNET`, kullanılan subnet, real scan ve honeypot ayarları, Nmap/Npcap/Scapy erişilebilirliği, OpenCanary log yolu, logs klasörü ve son `NetworkScan` / `MonitoringCycleRun` / `RiskSnapshot` kayıtlarını OK/WARNING/ERROR olarak raporlar. Aynı kontroller web arayüzünde **Ayarlar > Sistem Sağlığı** tablosunda görünür.

Nmap bulunamazsa Windows'ta PATH ve Npcap kurulumunu kontrol edin. OpenCanary log dosyası yoksa bu tek başına hata değildir; henüz log üretilmemiş olabilir veya `OPENCANARY_LOG_PATH` farklı bir dosyayı gösteriyor olabilir.

## Cihaz Envanteri

Cihazlar sayfası real modda yalnızca kullanılan subnet içindeki kayıtları ana listede gösterir. Eski veya farklı subnet kayıtları silinmez; ana dashboard sayıları ve cihaz listesi gerçek çalışma kapsamına göre filtrelenir. Bir cihaz son gerçek taramada görülürse `online`, daha önce görülmüş ama son taramada görülmemişse `offline` kabul edilir. Offline'a çekilen cihazın `last_seen` zamanı korunur; böylece cihazın en son gerçekten ne zaman görüldüğü kaybolmaz.

Cihaz envanterinde tüm/online/offline/yeni/uyarısı olan cihaz filtreleri, son taramada görülme bilgisi ve bağlı aktif uyarı sayısı bulunur. Cihaz detayında ilişkili uyarılar ve IP/MAC değişimi gibi güvenlik olayları incelenebilir.

## Uyarı Yönetimi

Uyarılar `active`, `acknowledged` veya `resolved` durumunda tutulur. `active` henüz ele alınmamış uyarıdır; `acknowledged` kullanıcının gördüğü ve incelemeye aldığı uyarıdır; `resolved` kapatılmış uyarıdır. Dashboard aktif uyarı sayısı yalnızca real-scope içindeki `status="active"` kayıtları sayar; acknowledged/resolved ve demo/fallback kapsam dışı kayıtlar bu sayıya girmez.

Uyarılar sayfasında filtreleme yapılabilir ve her uyarı POST aksiyonlarıyla “İncelendi”, “Çözüldü” veya “Aktif yap” durumuna alınabilir. Cihaz detay sayfasındaki ilişkili uyarılar için de aynı aksiyonlar kullanılabilir.

## Test

```powershell
python manage.py check
python manage.py test
python manage.py makemigrations
python manage.py migrate
python manage.py run_network_scan
python manage.py ingest_honeypot_logs
python manage.py analyze_security
python manage.py check_runtime_health
python manage.py run_monitoring_cycle --scan-limit 10
```

Bu sistem yalnızca kullanıcının kendi yerel ağı veya açıkça izin verilmiş test ağlarında kullanılmalıdır.
