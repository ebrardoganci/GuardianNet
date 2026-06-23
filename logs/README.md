# OpenCanary logları

Opsiyonel OpenCanary container'ı JSON satırlarını bu klasördeki `opencanary.log` dosyasına yazar. `docker-compose.yml` host tarafında `./logs` klasörünü container içinde `/var/tmp/opencanary` yoluna bağlar; OpenCanary config'i `/var/tmp/opencanary/opencanary.log` dosyasına yazar. Bu yol `.env` içindeki `OPENCANARY_LOG_PATH=logs/opencanary.log` değeriyle uyumludur.

Log dosyaları kaynak kontrole eklenmemelidir. Django, dosya yokken real modda fake/demo honeypot olayı üretmez; dashboard boş durum gösterir.
OpenCanary başlangıç/lifecycle satırları JSON olsa bile gerçek bağlantı olayı değildir; GuardianNet ingestion bunları `ignored` olarak sayar.

`opencanary.sample.jsonl` yalnızca parser testi için güvenli örnek satırlar içerir ve otomatik olarak okunmaz.
