from django.db import models


class Device(models.Model):
    STATUS_CHOICES = [
        ("online", "Online"),
        ("offline", "Offline"),
        ("unknown", "Bilinmiyor"),
    ]

    ip_address = models.GenericIPAddressField(
        verbose_name="IP Adresi"
    )

    mac_address = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name="MAC Adresi"
    )

    hostname = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name="Cihaz Adı"
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="unknown",
        verbose_name="Durum"
    )

    risk_score = models.IntegerField(
        default=0,
        verbose_name="Risk Skoru"
    )

    first_seen = models.DateTimeField(
        auto_now_add=True,
        verbose_name="İlk Görülme"
    )

    last_seen = models.DateTimeField(
        auto_now=True,
        verbose_name="Son Görülme"
    )

    def __str__(self):
        return f"{self.ip_address} - {self.hostname or 'Bilinmeyen Cihaz'}"


class Alert(models.Model):
    SEVERITY_CHOICES = [
        ("low", "Düşük"),
        ("medium", "Orta"),
        ("high", "Yüksek"),
        ("critical", "Kritik"),
    ]

    ALERT_TYPE_CHOICES = [
        ("new_device", "Yeni Cihaz"),
        ("port_scan", "Port Tarama"),
        ("arp_spoof", "ARP Spoofing"),
        ("suspicious_traffic", "Şüpheli Trafik"),
        ("system", "Sistem"),
    ]

    device = models.ForeignKey(
        Device,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="alerts",
        verbose_name="İlgili Cihaz"
    )

    alert_type = models.CharField(
        max_length=50,
        choices=ALERT_TYPE_CHOICES,
        verbose_name="Uyarı Tipi"
    )

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="low",
        verbose_name="Seviye"
    )

    title = models.CharField(
        max_length=150,
        verbose_name="Başlık"
    )

    message = models.TextField(
        verbose_name="Mesaj"
    )

    is_resolved = models.BooleanField(
        default=False,
        verbose_name="Çözüldü mü?"
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Oluşturulma Tarihi"
    )

    def __str__(self):
        return f"{self.title} - {self.get_severity_display()}"


class SecurityEvent(models.Model):
    LEVEL_CHOICES = [
        ("info", "Bilgi"),
        ("warning", "Uyarı"),
        ("danger", "Tehlike"),
    ]

    title = models.CharField(
        max_length=150,
        verbose_name="Olay Başlığı"
    )

    description = models.TextField(
        verbose_name="Açıklama"
    )

    level = models.CharField(
        max_length=20,
        choices=LEVEL_CHOICES,
        default="info",
        verbose_name="Seviye"
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Oluşturulma Tarihi"
    )

    def __str__(self):
        return f"{self.title} - {self.get_level_display()}"
