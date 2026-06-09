# RAG ile Tahmine Dayalı Log Analizi

Bu proje, siber güvenlik loglarının analiz edilmesi, tehditlerin tespit edilmesi ve olası risklerin öngörülmesi amacıyla geliştirilmiş Retrieval-Augmented Generation (RAG) tabanlı bir güvenlik asistanıdır.

---

## Proje Özeti

Sistem, Büyük Dil Modellerini (LLM), tehdit istihbaratı kaynaklarını ve hibrit bilgi erişim tekniklerini birleştirerek güvenlik loglarını analiz eder ve bağlama uygun açıklamalar üretir.

Projede aşağıdaki kaynaklar kullanılmaktadır:

* MITRE ATT&CK
* CISA Known Exploited Vulnerabilities (KEV)
* Özel tehdit raporları

---

## Özellikler

### Hibrit Arama

* BM25 anahtar kelime araması
* ChromaDB vektör araması
* Reciprocal Rank Fusion (RRF)

### Tehdit İstihbaratı Entegrasyonu

* MITRE ATT&CK
* CISA KEV
* Özel tehdit raporları

### IOC Çıkarımı

Sistem aşağıdaki göstergeleri otomatik olarak tespit eder:

* IPv4 / IPv6 adresleri
* Alan adları
* URL'ler
* E-posta adresleri
* CVE numaraları
* MITRE Teknik Kimlikleri
* MD5 / SHA1 / SHA256 özetleri

### Tahmine Dayalı Analiz

Sistem yalnızca mevcut olayları açıklamakla kalmaz, aynı zamanda saldırı eğilimlerini değerlendirerek olası güvenlik riskleri hakkında öngörüler sunar.

### Değerlendirme ve İzlenebilirlik

* Sorgu kayıtları
* Gecikme ölçümleri
* Kaynak gösterimi
* Performans değerlendirmesi

---

## Mimari

```text
Güvenlik Logları
       │
       ▼
IOC Çıkarımı
       │
       ▼
Hibrit Arama
(BM25 + ChromaDB)
       │
       ▼
Tehdit İstihbaratı
(MITRE + CISA)
       │
       ▼
LLM Analizi
       │
       ▼
Tehdit Tespiti ve Risk Tahmini
```

---

## Kullanılan Teknolojiler

* Python
* LangChain
* ChromaDB
* BM25
* Streamlit
* Groq / OpenAI / Ollama
* HuggingFace Embeddings

---

## Yapay Zeka Kullanımı

Bu projede üretken yapay zeka araçları aşağıdaki amaçlarla kullanılmıştır:

* Dokümantasyon geliştirme
* Hata ayıklama
* Literatür araştırması

Sistem tasarımı, entegrasyon, geliştirme ve değerlendirme çalışmaları için kullanılmıştır.

---

## Geliştirici

Muğla Sıtkı Koçman Üniversitesi

Bilgisayar Mühendisliği Bölümü

2025–2026 Bahar Dönemi Projesi
