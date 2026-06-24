# GuardianNet

## Project Overview / Proje Özeti

GuardianNet, izinli lokal ağlarda cihaz keşfi, honeypot log takibi, güvenlik olayı analizi ve risk puanı üretimi yapan Django tabanlı savunma projesidir. Proje gerçek saldırı aracı değildir; exploit, parola denemesi, kalıcılık, zararlı yazılım veya izinsiz tarama gerçekleştirmez.

## Features

- Login page ve Django auth tabanlı oturum.
- Dashboard üzerinde genel ağ durumu, cihaz sayıları, risk/güvenlik puanı ve son monitoring cycle özeti.
- Devices page ile IP, MAC, hostname/vendor, online/offline, ilk/son görülme ve yeni/bilinmeyen cihaz etiketi.
- Alerts page ile yeni cihaz, SSH honeypot, SSH brute force şüphesi, port tarama davranışı ve ARP spoofing şüphesi uyarıları.
- Reports page ile Chart.js grafiklerinde günlük olay, risk geçmişi, cihaz durumu ve honeypot servis dağılımı.
- OpenCanary honeypot entegrasyonu: SSH, HTTP ve FTP sahte servisleri.
- Monitoring cycle: network scan + honeypot ingest + analysis + risk update.
- Real mode'da demo/fallback veri üretmeden çalışma.

## Technology Stack

- Python, Django, SQLite
- Nmap host discovery ve Scapy ARP discovery
- Docker Desktop ve OpenCanary
- Chart.js
- Windows Task Scheduler için `.bat` script desteği

## Architecture

- `dashboard/models.py`: Device, Alert, SecurityEvent, HoneypotEvent, RiskSnapshot, MonitoringCycleRun modelleri.
- `dashboard/services/network_scanner.py`: izinli özel subnet içinde cihaz keşfi ve yeni/bilinmeyen cihaz uyarısı.
- `dashboard/services/honeypot_manager.py`: OpenCanary JSON log ingest işlemi.
- `dashboard/services/security_analysis.py`: ARP, port scan, SSH attempt/brute force ve risk analizi.
- `dashboard/services/risk_engine.py`: risk skoru ve güvenlik puanı üretimi.
- `docker-compose.yml` ve `opencanary/opencanary.conf`: lokal OpenCanary servisleri.

## Environment Configuration

Proje kökündeki `.env` otomatik okunur ve kaynak kontrole eklenmez.

```env
GUARDIANNET_MODE=real
LOCAL_SUBNET=192.168.1.0/24
ENABLE_REAL_SCAN=True
ENABLE_HONEYPOT_LOGS=True
OPENCANARY_LOG_PATH=logs/opencanary.log
MONITORING_CYCLE_SCAN_LIMIT=10
PORT_SCAN_THRESHOLD=6
BRUTE_FORCE_THRESHOLD=5
DETECTION_WINDOW_MINUTES=10
OPENCANARY_FTP_PORT=2121
OPENCANARY_SSH_PORT=2222
OPENCANARY_HTTP_PORT=8080
```

`LOCAL_SUBNET` uygulama koduna sabitlenmez; `.env` veya runtime settings içinden gelir.

## Demo Mode vs Real Mode

- **Real mode:** Yalnızca kullanıcının kendi izinli RFC1918 özel ağı için host discovery yapar. Public IP taranmaz. Nmap/Scapy/OpenCanary yoksa demo/fallback veri üretmez.
- **Demo mode:** Dokümantasyon IP bloklarından örnek kayıt üretir. Gerçek ağ veya gerçek honeypot sonucu gibi kullanılmamalıdır.

## Local Network Scan

Komutlar `manage.py` dosyasının bulunduğu dizinde çalıştırılır:

```powershell
cd GuardianNet\GuardianNet
python manage.py run_network_scan
```

Nmap varsa `nmap -sn` ile yalnızca host discovery yapılır. Nmap yoksa Scapy ARP discovery denenir. Port taraması veya saldırı işlemi yapılmaz.

## Honeypot with OpenCanary

OpenCanary Docker ile çalışır. SSH, HTTP ve FTP sahte servisleri lokal geliştirme için şu host portlarını kullanır:

- SSH: `2222`
- HTTP: `8080`
- FTP: `2121`

Başlatma:

```powershell
docker compose up --build -d
docker compose ps
docker compose logs --tail=100
```

Durdurma:

```powershell
docker compose down
```

Port çakışması olursa `.env` içindeki `OPENCANARY_SSH_PORT`, `OPENCANARY_HTTP_PORT` veya `OPENCANARY_FTP_PORT` değerini kendi makinenize göre değiştirin. OpenCanary log hedefi `logs/opencanary.log` dosyasıdır ve bu dosya commitlenmez.

## Dashboard

Dashboard şu bilgileri gösterir:

- Genel ağ durumu ve aktif cihaz sayısı
- Risk seviyesi ve güvenlik puanı
- Honeypot durumu
- Son monitoring cycle özeti
- Son honeypot olayları
- Son saldırı / güvenlik olayları
- "SSH bağlantı denemesi algılandı" uyarısı

Dashboard üzerindeki **Monitoring Cycle Çalıştır** butonu network scan + honeypot ingest + analysis + risk update akışını çalıştırır.

## Devices Page

Devices page, izinli lokal ağ kapsamındaki cihazları listeler. IP, MAC, hostname/vendor, online/offline durum, ilk görülme, son görülme, son taramada görülme, aktif uyarı sayısı ve yeni/bilinmeyen cihaz etiketi gösterilir.

## Alerts Page

Alerts page, teknik olmayan kullanıcı için "ne olmuş?" sorusuna cevap veren özetlerle çalışır:

- Yeni/bilinmeyen cihaz ağa bağlandı
- SSH bağlantı denemesi algılandı
- Olası SSH brute force denemesi
- Olası port tarama davranışı
- Olası ARP spoofing şüphesi

Uyarılar `active`, `acknowledged` veya `resolved` durumuna alınabilir.

## Reports Page

Reports page Chart.js ile şu grafikleri gösterir:

- Günlük honeypot / güvenlik olayı sayısı
- Risk skoru geçmişi
- Cihaz durumu
- Honeypot servis dağılımı

Veri yoksa grafik yerine "Henüz raporlanacak veri yok." mesajı gösterilir. JSON chart verileri Django `json_script` filtresiyle güvenli aktarılır.

## Running a Monitoring Cycle Manually

```powershell
cd GuardianNet\GuardianNet
python manage.py run_monitoring_cycle --scan-limit 10
```

`--scan-limit` cihaz sayısını sabitlemez; taranacak host hedeflerini sınırlar. Gerektiğinde `--skip-scan`, `--skip-honeypot` veya `--skip-analysis` kullanılabilir.

## Running from the Dashboard

Dashboard ana sayfasındaki **Monitoring Cycle Çalıştır** butonu aynı monitoring cycle servis akışını POST ile çalıştırır. Başarılı çalıştırmadan sonra yeşil mesajda scan, honeypot ingest ve risk özeti gösterilir.

## Windows Task Scheduler Setup

`scripts\run_guardian_cycle.bat` dosyası zamanlanmış çalıştırma için hazırdır. Script repo kökünü kendi konumundan bulur, `GuardianNet\GuardianNet` klasörüne geçer ve çıktıyı `logs\monitoring_cycle_task.log` dosyasına ekler.

Scripti farklı bir konuma taşırsanız veya kendi bilgisayarınızda sabit yol kullanmak isterseniz path değişkenlerini kendi repo yolunuza göre düzenleyin.

Task Scheduler:

1. Task Scheduler aç.
2. Create Basic Task seç.
3. Trigger olarak 15/30/60 dakika veya günlük seç.
4. Action: Start a program.
5. Program/script: `scripts\run_guardian_cycle.bat` tam dosya yolu.
6. Start in: repo kökü veya `scripts` klasörü.
7. Test için görevi manuel **Run** et.

## Safe Honeypot Demo Scenario

Bu demo yalnızca kendi lokal makinenizdeki OpenCanary honeypot için yapılmalıdır.

```powershell
ssh fakeadmin@127.0.0.1 -p 2222
```

Windows port kontrolü:

```powershell
Test-NetConnection 127.0.0.1 -Port 2222
```

Sonra:

```powershell
cd GuardianNet\GuardianNet
python manage.py run_monitoring_cycle --scan-limit 10
```

Dashboard'da honeypot event, "SSH bağlantı denemesi algılandı" uyarısı ve risk skoru kontrol edilir.

## Tests

```powershell
cd GuardianNet\GuardianNet
python manage.py makemigrations --check --dry-run
python manage.py check
python manage.py test
python manage.py run_monitoring_cycle --scan-limit 10
```

## Safety Notes

- Yalnızca izinli lokal ortamda kullanın.
- Kamu IP'leri, okul ağı veya izinsiz sistemlerde tarama/saldırı yapmayın.
- `.env` commitlenmez.
- `logs/opencanary.log` commitlenmez.
- `logs/monitoring_cycle_task.log` commitlenmez.
- Real mode'da demo/fallback veri üretilmez.
- GuardianNet saldırı üretmez; yalnızca izinli kaynaklardan gelen gözlem ve logları analiz eder.

## Limitations / Future Work

- ARP spoofing analizi mevcut IP/MAC gözlemlerine bağlıdır; MAC bilgisi yoksa güvenilir ARP analizi yapılamaz.
- Risk puanı açıklanabilir basit kurallarla hesaplanır; üretim SIEM korelasyonu değildir.
- OpenCanary HTTP/FTP servisleri yapılandırılmıştır; demo odağı SSH honeypot üzerindedir.
- Daha geniş kurumsal kullanım için merkezi log saklama, rol tabanlı yetki ve gelişmiş raporlama eklenebilir.
