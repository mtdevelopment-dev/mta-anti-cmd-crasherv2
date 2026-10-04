# MTA:SA Server Shield (x64)

MTA:SA (Multi Theft Auto: San Andreas) 64-bit sunucuları (Windows & Linux) için geliştirilmiş, bilinen ve aktif kullanılan bellek taşması, paket manipülasyonu ve Lua çekirdek çökertme yöntemlerine karşı koruma sağlayan C++ modülüdür.

---

## 🛡️ Engellenen Güvenlik Açıkları

Bu modül, MTA çekirdeğine dinamik bellek kancaları (hook), socket seviyesinde paket filtresi ve güvenli SEH/VEH/POSIX sinyal yakalayıcıları yerleştirerek sunucunun çökmesini engeller:

### 1. Cascade (BitStream Buffer Overflow & Oversized Datagrams)
- **Hedef:** `net.dll` / `net.so` (`BitStream::WriteBits`, `recvfrom`)
- **Tehdit:** Negatif veya aşırı büyük bit sayısı gönderilerek `numberOfBitsToWrite` hesaplamasında integer overflow oluşturulması veya aşırı büyük UDP datagramları ile `0xC0000005` (Access Violation), `0xC0000374` (Heap Corruption) ya da Linux'ta `SIGSEGV` çökmesi.
- **Çözüm:** Socket seviyesinde 4096 bayttan büyük geçersiz datagramlar filtrelenir; bellek taşması ve integer overflow parametreleri normalize edilerek paketler güvenle düşürülür.

### 2. Pulse Strike (Entity Deserializer Exploit)
- **Hedef:** `deathmatch.dll` / `deathmatch.so`
- **Tehdit:** Bozuk veya sahte entity pointer'ları (`0x414141414140` vb.) üzerinden okuma/yazma yapmaya zorlayarak çökme oluşturulması.
- **Çözüm:** Pointer doğrulama ve güvenli SEH / Linux Signal (`SIGSEGV`/`SIGBUS`) kancaları eklenerek geçersiz nesne verileri ayıklanır; sunucu kesintiye uğramadan paket yok sayılır.

### 3. Whisper (Lua nil / NaN Key Crash)
- **Hedef:** `lua5.1.dll` (`luaH_set`) ve Lua Panic Handler
- **Tehdit:** Lua tablolarına `nil` veya `NaN` (Not a Number) anahtarlar gönderilerek Lua sanal makinesinin `table index is nil / NaN` panik hatasına düşmesi ve sunucu konsolunun aniden kapanması.
- **Çözüm:** `luaH_set` kancalanarak geçersiz ve sayısal olmayan anahtarlar güvenli sahte bir havuza yönlendirilir; panic handler güvenli hale getirilerek sunucunun çalışmaya devam etmesi sağlanır.

---

## 📁 Proje Yapısı

```text
mta_server_shield/
├── bin/
│   └── x64/
│       ├── mta_server_shield.dll   # Windows x64 modülü
│       └── mta_server_shield.so    # Linux x64 modülü (derleme sonrası)
├── src/
│   └── mta_server_shield.cpp       # Platformlar arası C++ kaynak kodu (Win + Linux)
├── .gitignore                      # Git filtreleri
├── build.bat                       # Windows MSVC otomatik derleme scripti
├── build.sh                        # Linux GCC/Clang otomatik derleme scripti
├── Makefile                        # Linux makefile derleme dosyası
└── README.md                       # Dokümantasyon
```

---

## 🚀 Kurulum

### 🪟 Windows Sunucular İçin:
1. `bin/x64/mta_server_shield.dll` dosyasını sunucunuzun `x64/modules/` (veya `modules/`) klasörüne kopyalayın.
2. `mtaserver.conf` dosyasını açıp `<modules>` etiketinin içine ekleyin:
```xml
<module src="mta_server_shield.dll" />
```
3. Sunucuyu başlatın.

### 🐧 Linux Sunucular İçin (Ubuntu, Debian, CentOS):
1. `bin/x64/mta_server_shield.so` dosyasını Linux sunucunuzun `x64/modules/` (veya `modules/`) klasörüne kopyalayın.
2. `mtaserver.conf` dosyasını açıp `<modules>` etiketinin içine ekleyin:
```xml
<module src="mta_server_shield.so" />
```
3. Alternatif olarak soket seviyesinde doğrudan yükleme için:
```bash
LD_PRELOAD=./x64/modules/mta_server_shield.so ./mta-server64
```
4. Sunucuyu başlatın. Konsol çıktısında yeşil renkle banner ve korumanın devrede olduğu görüntülenecektir:
```text
[MTGuard] AKTIF & KORUMA CALISIYOR (LINUX)
```

---

## 🛠️ Kaynak Koddan Derleme

### Windows (MSVC x64):
1. Proje ana dizininde `build.bat` dosyasını çalıştırın (veya `x64 Native Tools Command Prompt for VS`).
2. Çıktı: `bin/x64/mta_server_shield.dll`

### Linux (GCC / Clang):
Sunucunuzda derlemek için:
```bash
# Gerekli araçları yükleyin (Ubuntu / Debian):
sudo apt update && sudo apt install -y build-essential

# Derleyin:
make
# veya
chmod +x build.sh && ./build.sh
```
Çıktı otomatik olarak `bin/x64/mta_server_shield.so` konumuna kaydedilir.

---

## 📜 Lisans

Bu proje eğitim ve sunucu güvenliği araştırma amaçları için geliştirilmiştir. Açık kaynak olarak serbestçe kullanılabilir ve geliştirilebilir.
