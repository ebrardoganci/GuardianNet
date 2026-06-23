from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class Device(models.Model):
    STATUS_CHOICES = [("online", "Online"), ("offline", "Offline"), ("unknown", "Bilinmiyor")]

    ip_address = models.GenericIPAddressField("IP adresi", unique=True)
    mac_address = models.CharField("MAC adresi", max_length=50, blank=True, null=True)
    hostname = models.CharField("Cihaz adi", max_length=100, blank=True, null=True)
    vendor = models.CharField("Uretici", max_length=100, blank=True)
    status = models.CharField("Durum", max_length=20, choices=STATUS_CHOICES, default="unknown")
    is_trusted = models.BooleanField("Guvenilir", default=False)
    risk_score = models.PositiveSmallIntegerField(
        "Risk skoru", default=0, validators=[MaxValueValidator(100)]
    )
    first_seen = models.DateTimeField("Ilk gorulme", auto_now_add=True)
    last_seen = models.DateTimeField("Son gorulme", auto_now=True)

    class Meta:
        ordering = ["-last_seen"]

    def __str__(self):
        return f"{self.ip_address} - {self.hostname or 'Bilinmeyen Cihaz'}"


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Dusuk"), ("medium", "Orta"), ("high", "Yuksek"), ("critical", "Kritik")
    ]
    ALERT_TYPE_CHOICES = [
        ("new_device", "Yeni Cihaz"), ("port_scan", "Port Tarama Tespiti"),
        ("arp_spoof", "ARP Anomali Tespiti"), ("brute_force", "Kaba Kuvvet Tespiti"),
        ("suspicious_traffic", "Supheli Trafik"), ("honeypot", "Honeypot"), ("system", "Sistem"),
    ]
    STATUS_CHOICES = [("active", "Aktif"), ("acknowledged", "Incelendi"), ("resolved", "Cozuldu")]

    device = models.ForeignKey(Device, on_delete=models.SET_NULL, blank=True, null=True, related_name="alerts")
    alert_type = models.CharField("Uyari tipi", max_length=50, choices=ALERT_TYPE_CHOICES)
    severity = models.CharField("Seviye", max_length=20, choices=SEVERITY_CHOICES, default="low")
    status = models.CharField("Durum", max_length=20, choices=STATUS_CHOICES, default="active")
    title = models.CharField("Baslik", max_length=150)
    message = models.TextField("Mesaj")
    source_ip = models.GenericIPAddressField("Kaynak IP", blank=True, null=True)
    source_mac = models.CharField("Kaynak MAC", max_length=50, blank=True)
    is_resolved = models.BooleanField("Cozuldu", default=False)
    created_at = models.DateTimeField("Olusturulma tarihi", auto_now_add=True)
    updated_at = models.DateTimeField("Guncellenme tarihi", auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        self.is_resolved = self.status == "resolved"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.title} - {self.get_severity_display()}"


class SecurityEvent(models.Model):
    LEVEL_CHOICES = [("info", "Bilgi"), ("warning", "Uyari"), ("danger", "Tehlike")]
    EVENT_TYPE_CHOICES = [
        ("network", "Ag Olayi"), ("port_scan", "Port Tarama Tespiti"),
        ("arp_anomaly", "ARP Anomalisi"), ("brute_force", "Kaba Kuvvet Tespiti"),
        ("honeypot", "Honeypot"), ("system", "Sistem"),
    ]

    event_type = models.CharField("Olay tipi", max_length=50, choices=EVENT_TYPE_CHOICES, default="system")
    title = models.CharField("Olay basligi", max_length=150)
    description = models.TextField("Aciklama")
    level = models.CharField("Seviye", max_length=20, choices=LEVEL_CHOICES, default="info")
    source_ip = models.GenericIPAddressField("Kaynak IP", blank=True, null=True)
    source_mac = models.CharField("Kaynak MAC", max_length=50, blank=True)
    destination_ip = models.GenericIPAddressField("Hedef IP", blank=True, null=True)
    destination_port = models.PositiveIntegerField("Hedef port", blank=True, null=True)
    protocol = models.CharField("Protokol", max_length=20, blank=True)
    risk_score = models.PositiveSmallIntegerField(
        "Risk skoru", default=0, validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    created_at = models.DateTimeField("Olusturulma tarihi", auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} - {self.get_level_display()}"


class NetworkScan(models.Model):
    STATUS_CHOICES = [("demo", "Demo"), ("completed", "Tamamlandi"), ("failed", "Basarisiz")]

    network_range = models.CharField("Ag araligi", max_length=64, default="demo-network")
    status = models.CharField("Durum", max_length=20, choices=STATUS_CHOICES, default="demo")
    devices_found = models.PositiveIntegerField("Bulunan cihaz", default=0)
    is_mock = models.BooleanField("Mock veri", default=True)
    scan_method = models.CharField("Tarama yontemi", max_length=30, blank=True)
    message = models.CharField("Aciklama", max_length=255, blank=True)
    notes = models.TextField("Notlar", blank=True)
    started_at = models.DateTimeField("Baslangic", auto_now_add=True)
    completed_at = models.DateTimeField("Bitis", blank=True, null=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"{self.network_range} - {self.get_status_display()}"


class HoneypotEvent(models.Model):
    SERVICE_CHOICES = [("ssh", "SSH"), ("http", "HTTP"), ("ftp", "FTP")]

    event_id = models.CharField("Log kimligi", max_length=64, unique=True, blank=True, null=True)
    source_ip = models.GenericIPAddressField("Kaynak IP")
    service = models.CharField("Servis", max_length=20, choices=SERVICE_CHOICES)
    username = models.CharField("Kullanici adi", max_length=100, blank=True)
    command = models.CharField("Kaydedilen istek/komut", max_length=255, blank=True)
    destination_port = models.PositiveIntegerField("Hedef port", blank=True, null=True)
    login_success = models.BooleanField("Giris basarili", default=False)
    raw_data = models.JSONField("Ham log", default=dict, blank=True)
    is_mock = models.BooleanField("Mock veri", default=True)
    created_at = models.DateTimeField("Olusturulma tarihi", auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.source_ip} - {self.service}"


class SystemSetting(models.Model):
    key = models.CharField("Anahtar", max_length=100, unique=True)
    value = models.CharField("Deger", max_length=255)
    description = models.CharField("Aciklama", max_length=255, blank=True)
    updated_at = models.DateTimeField("Guncellenme", auto_now=True)

    class Meta:
        ordering = ["key"]

    def __str__(self):
        return self.key


class RiskSnapshot(models.Model):
    risk_level = models.CharField("Risk seviyesi", max_length=20, default="low")
    risk_score = models.PositiveSmallIntegerField(
        "Risk skoru", default=0, validators=[MaxValueValidator(100)]
    )
    security_score = models.PositiveSmallIntegerField(
        "Guvenlik puani", default=100, validators=[MaxValueValidator(100)]
    )
    active_alerts = models.PositiveIntegerField("Aktif uyari", default=0)
    recorded_at = models.DateTimeField("Kayit zamani", auto_now_add=True)

    class Meta:
        ordering = ["-recorded_at"]

    def __str__(self):
        return f"{self.recorded_at:%Y-%m-%d %H:%M} - {self.risk_score}"


class MonitoringCycleRun(models.Model):
    STATUS_CHOICES = [
        ("completed", "Tamamlandi"),
        ("partial", "Kismi"),
        ("failed", "Basarisiz"),
    ]
    STEP_STATUS_CHOICES = [
        ("pending", "Bekliyor"),
        ("completed", "Tamamlandi"),
        ("skipped", "Atlandi"),
        ("failed", "Basarisiz"),
    ]

    started_at = models.DateTimeField("Baslangic", auto_now_add=True)
    completed_at = models.DateTimeField("Bitis", blank=True, null=True)
    status = models.CharField("Durum", max_length=20, choices=STATUS_CHOICES, default="failed")
    scan_status = models.CharField("Scan durumu", max_length=20, choices=STEP_STATUS_CHOICES, default="pending")
    scan_found_devices = models.PositiveIntegerField("Bulunan cihaz", default=0)
    scan_new_devices = models.PositiveIntegerField("Yeni cihaz", default=0)
    honeypot_status = models.CharField("Honeypot durumu", max_length=20, choices=STEP_STATUS_CHOICES, default="pending")
    honeypot_read_lines = models.PositiveIntegerField("Okunan log satiri", default=0)
    honeypot_created_events = models.PositiveIntegerField("Eklenen honeypot olayi", default=0)
    honeypot_duplicates = models.PositiveIntegerField("Duplicate honeypot olayi", default=0)
    honeypot_parse_errors = models.PositiveIntegerField("Honeypot parse hatasi", default=0)
    analysis_status = models.CharField("Analiz durumu", max_length=20, choices=STEP_STATUS_CHOICES, default="pending")
    arp_alerts = models.PositiveIntegerField("ARP bulgusu", default=0)
    port_alerts = models.PositiveIntegerField("Port bulgusu", default=0)
    ssh_alerts = models.PositiveIntegerField("SSH bulgusu", default=0)
    risk_score = models.PositiveSmallIntegerField("Risk skoru", default=0, validators=[MaxValueValidator(100)])
    error_summary = models.TextField("Hata ozeti", blank=True)
    raw_summary = models.JSONField("Ham ozet", default=dict, blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"{self.started_at:%Y-%m-%d %H:%M} - {self.status}"

    @property
    def honeypot_ignored_lines(self):
        honeypot = (self.raw_summary or {}).get("honeypot") or {}
        try:
            return int(honeypot.get("ignored", 0) or 0)
        except (TypeError, ValueError):
            return 0
