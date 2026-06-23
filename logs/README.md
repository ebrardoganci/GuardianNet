# OpenCanary logları

Opsiyonel OpenCanary container'ı JSON satırlarını bu klasördeki `opencanary.log` dosyasına yazar. Log dosyaları kaynak kontrole eklenmemelidir. Django, dosya yokken real modda fake/demo honeypot olayı üretmez; dashboard boş durum gösterir.

`opencanary.sample.jsonl` yalnızca parser testi için güvenli örnek satırlar içerir ve otomatik olarak okunmaz.
