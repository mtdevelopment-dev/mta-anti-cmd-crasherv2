# MTA:SA Server Shield (x64)

MTA:SA (Multi Theft Auto: San Andreas) 64-bit sunucuları için geliştirilmiş, bilinen ve aktif kullanılan bellek taşması, paket manipülasyonu ve Lua çekirdek çökertme yöntemlerine karşı koruma sağlayan C++ modülüdür.

---

## 🛡️ Engellenen Güvenlik Açıkları

Bu modül, MTA çekirdeğine dinamik bellek kancaları (hook) ve güvenli SEH/VEH hata yakalayıcıları yerleştirerek sunucunun çökmesini engeller:

### 1. Cascade (BitStream Buffer Overflow)
- **Hedef Modül:** `net.dll + 0x3A6B0` (`BitStream::WriteBits`)
- **Tehdit:** Negatif veya aşırı büyük bit sayısı gönderilerek `numberOfBitsToWrite` hesaplamasında integer overflow oluşturulması, neticesinde `0xC0000005` (Access Violation) ve `0xC0000374` (Heap Corruption) çökmesi.
- **Çözüm:** Giriş parametreleri normalize edilir, maksimum sınır kontrolü uygulanır ve bellek taşması gerçekleşmeden önce geçersiz paketler sessizce düşürülür.

### 2. Pulse Strike (Entity Deserializer Exploit)
- **Hedef Modül:** `deathmatch.dll + 0x1A4110` ve `0x1A25B0`
- **Tehdit:** Bozuk veya sahte entity pointer'ları (`0x414141414140` vb.) üzerinden okuma/yazma yapmaya zorlayarak `0xC0000005` çökmesi oluşturulması.
- **Çözüm:** Pointer doğrulama ve güvenli SEH kancaları eklenerek geçersiz nesne verileri ayıklanır; sunucu kesintiye uğramadan paket yok sayılır.

### 3. Whisper (Lua nil / NaN Key Crash)
- **Hedef Modül:** `lua5.1.dll + 0x179C0` (`luaH_set`) ve Lua Panic Handler (`lua5.1.dll + 0xB704`)
- **Tehdit:** Lua tablolarına `nil` veya `NaN` (Not a Number) anahtarlar gönderilerek Lua sanal makinesinin `table index is nil / NaN` panik hatasına düşmesi ve sunucu konsolunun aniden kapanması.
- **Çözüm:** `luaH_set` kancalanarak geçersiz ve sayısal olmayan anahtarlar güvenli sahte bir havuza yönlendirilir; panic handler güvenli hale getirilerek sunucunun çalışmaya devam etmesi sağlanır.

---

## 📁 Proje Yapısı

```text
mta_server_shield/
├── bin/
│   └── x64/
│       └── mta_server_shield.dll   # Hazır derlenmiş x64 modülü
├── src/
│   └── mta_server_shield.cpp       # Koruma modülü C++ kaynak kodu
├── .gitignore                      # Git geçici dosya filtresi
├── build.bat                       # Otomatik MSVC derleme scripti
└── README.md                       # Dokümantasyon
```

---

## 🚀 Kurulum

1. `bin/x64/mta_server_shield.dll` dosyasını kopyalayın ve sunucunuzun `x64/modules/` klasörüne yapıştırın.
2. Sunucu ana dizinindeki `mtaserver.conf` dosyasını bir metin editörüyle açın.
3. `<modules>` bloğunun içerisine aşağıdaki satırı ekleyin:

```xml
<module src="mta_server_shield.dll" />
```

> **Not:** Eğer dosya adını farklı bir isimle kullanmak isterseniz (örneğin `ml_guard.dll`), hem dosya adını hem de `mtaserver.conf` içerisindeki `src` alanını aynı şekilde güncelleyebilirsiniz.

4. Sunucunuzu başlatın. Konsol çıktısında korumaların aktif edildiğini gösteren logları göreceksiniz:

```text
[MTGuard] Cascade exploit korumasi aktif edildi.
[MTGuard] Pulse Strike exploit korumasi aktif edildi.
[MTGuard] Lua table nil/NaN korumasi aktif edildi.
```

---

## 🛠️ Kaynak Koddan Derleme

Modülü sıfırdan derlemek için **Visual Studio (MSVC x64 C++ Araçları)** gereklidir:

1. Proje ana dizinindeki `build.bat` dosyasını çalıştırın (veya `x64 Native Tools Command Prompt for VS` üzerinden açın).
2. Script otomatik olarak `cl.exe` derleyicisini bulur, C++17 ve `/O2` optimizasyonuyla derler ve çıktıyı `bin/x64/mta_server_shield.dll` yoluna kaydeder.

---

## 📜 Lisans

Bu proje eğitim ve sunucu güvenliği araştırma amaçları için geliştirilmiştir. Açık kaynak olarak serbestçe kullanılabilir ve geliştirilebilir.
