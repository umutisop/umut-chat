UMUT CHAT - YAYINA HAZIRLAMA

DOSYALAR
- app.py: Flask uygulamasi
- requirements.txt: Python paketleri
- render.yaml: Render icin servis ve kalici disk ayarlari

RENDER'DA YAYINLAMA
1. Bu klasoru GitHub'a yeni bir repository olarak yukle.
2. Render hesabinda New > Blueprint sec ve GitHub repository'ni bagla.
3. Render, render.yaml dosyasini okuyarak servisi olusturur.
4. Deploy tamamlaninca Render'in verdigi https://...onrender.com adresini ac.
5. Ilk yonetici hesabi icin https://SITENIN-ADRESI/setup sayfasina git.
6. Render Dashboard > ilgili servis > Environment bolumunden ADMIN_SETUP_CODE degerini gor.
   Bu kodu ilk yonetici kurulum ekranina gir. SECRET_KEY degerini kimseyle paylasma.
7. Yonetici hesabi olustuktan sonra /admin sayfasindan davet baglantisi olustur.
8. Davet baglantisini istedigin kisiye gonder. Kisi farkli internetten ve telefondan katilabilir.

ONEMLI
- Render servisinde kalici disk tanimlidir; SQLite veritabani /var/data/umut_chat.db konumunda tutulur.
- SECRET_KEY ve ADMIN_SETUP_CODE degerlerini kimseyle paylasma.
- ADMIN_SETUP_CODE sadece ilk yonetici hesabini olusturmak icindir. Ilk yonetici olustuktan sonra /setup otomatik kapanir.
- Site internete acik olacagi icin yalnizca guvendigin kisilere davet ver.
- Uygulama kodu Python syntax kontrolunden gecmistir. Bu calisma ortaminda Flask kurulu olmadigi icin gercek sunucu baslatma ve canli internet testi yapilmamistir.
