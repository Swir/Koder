<div align="center">

# 🔐 Koder — Swirtv Encoder / Decoder

**Simple PyQt5 desktop file encoder/decoder using a repeating XOR key**  
**Prosty desktopowy koder/dekoder plików PyQt5 wykorzystujący powtarzający się klucz XOR**

![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)
![PyQt5](https://img.shields.io/badge/GUI-PyQt5-41CD52?logo=qt&logoColor=white)
![Format](https://img.shields.io/badge/output-.swirtv-ff4fa3)
![Author](https://img.shields.io/badge/Author-Swir-8A2BE2)

</div>

---

## 🇬🇧 English

Koder is a lightweight desktop utility for reversible file transformation. The user selects a file, enters a four-character key and can encode it into a `.swirtv` file or decode it again using the same key.

It is useful as a small **PyQt5 file encoder**, **XOR encoder/decoder**, **Python desktop utility**, or educational project demonstrating reversible binary-file transformation.

### ✨ Features
- graphical PyQt5 interface
- works with text and binary files
- encode and decode operations
- four-character user key
- background worker thread to keep the GUI responsive
- `.swirtv` output extension

### 🚀 Run
```bash
pip install -r requirements.txt
python koder.py
```

> **Security note:** XOR is suitable for experimentation and simple reversible obfuscation, but it is not modern cryptographic encryption. Do not use this program to protect sensitive data.

---

## 🇵🇱 Polski

Koder to lekkie narzędzie desktopowe do odwracalnego kodowania plików. Użytkownik wybiera plik, podaje czteroznakowy klucz, a następnie może zapisać zakodowaną wersję jako `.swirtv` lub przywrócić oryginał przy użyciu tego samego klucza.

Projekt może zainteresować osoby szukające **kodera plików PyQt5**, **enkodera/dekodera XOR**, prostego narzędzia desktopowego Python lub przykładu odwracalnej transformacji plików binarnych.

### ✨ Funkcje
- interfejs graficzny PyQt5
- obsługa plików tekstowych i binarnych
- kodowanie i dekodowanie
- czteroznakowy klucz użytkownika
- operacje wykonywane w osobnym wątku
- własne rozszerzenie `.swirtv`

### 🚀 Uruchomienie
```bash
pip install -r requirements.txt
python koder.py
```

> **Uwaga dotycząca bezpieczeństwa:** XOR nadaje się do nauki i prostej odwracalnej obfuskacji, ale nie jest współczesnym szyfrowaniem. Nie używaj programu do ochrony poufnych danych.

---

## 🔎 Discoverability / Keywords

`python` · `pyqt5` · `file encoder` · `file decoder` · `xor` · `xor encoder` · `desktop utility` · `binary files` · `file obfuscation` · `swirtv`

## 📁 Structure / Struktura
```text
Koder/
├── koder.py
├── requirements.txt
├── file exe/
└── README.md
```

## 👤 Author / Autor
Developed by **Swir**.
