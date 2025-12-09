# LEVIATHAN EDIT v7 — TOP SECRET // NOFORN PENTEST COMMAND CENTER

<img src="https://raw.githubusercontent.com/Railgun1337/leviathan-edit/main/screenshot.png" alt="LEVIATHAN EDIT in FBI Terminal theme" width="100%"/>

> **"The editor that looks like it was stolen from a three-letter agency."**

A hyper-stylized, classified-themed, offensive-security code editor built purely in Python/Tkinter. Designed for red teamers, pentesters, CTF players, and anyone who wants their text editor to feel like they just breached a SCIF.

### Features That Will Make You Question Your Current IDE

- 10 insane cyberpunk / government-black-ops themes (FBI Terminal, CIA BlackOps, NSA Quantum, Matrix Rain, Blood Agent…)
- Real-time Pygments syntax highlighting for 13 languages (Python, Bash, JS, C/C++, Go, Rust, PHP, SQL, etc.)
- Jedi-powered intelligent autocomplete (yes, real Python autocomplete in a Tkinter editor)
- Built-in classified payload template database (reverse shells, XSS, SQLi, LFI, command injection, Metasploit handlers, etc.)
- Custom template folder support — drop your own .py/.sh/.txt payloads and they instantly appear
- Base64 & URL encoder/decoder tools
- Live hash type identifier
- Custom background images with darkening filter (because you need that cyber aesthetic)
- Full window transparency control (ghost mode activated)
- Custom color picker for every element
- Line numbers with zero-day style formatting (00001, 00002…)
- Right-click → "Insert Template" menu with all payloads
- Font zoom, window scaling, and more

### Screenshot Gallery (You know you want it)


| FBI Terminal                | CIA BlackOps                  | NSA Quantum                   |
|-----------------------------|-------------------------------|-------------------------------|
| ![FBI] <img width="2393" height="1292" alt="Screenshot 2025-12-04 201922" src="https://github.com/user-attachments/assets/eee4ccaa-a1ef-4698-bb6b-2c26820a4503" /> | ![CIA] <img width="402" height="465" alt="Screenshot 2025-12-04 201950" src="https://github.com/user-attachments/assets/3c41ba44-93ee-4593-be18-84ede1a89a38" />
| ![NSA] <img width="1002" height="790" alt="Screenshot 2025-12-04 202008" src="https://github.com/user-attachments/assets/e1412012-9188-47f8-af03-eced627173d4" />
 | <img width="307" height="1237" alt="image" src="https://github.com/user-attachments/assets/d5fdbca8-fc8f-4bda-862e-19a24531a205" /> <img width="1592" height="167" alt="image" src="https://github.com/user-attachments/assets/42729843-95c5-4b9c-86cc-2daca5f6e750" /> <img width="441" height="1206" alt="image" src="https://github.com/user-attachments/assets/4f969a59-e542-40e6-958d-e56f7f4e7eeb" />


<img width="1991" height="1294" alt="Screenshot 2025-12-08 211532" src="https://github.com/user-attachments/assets/50132a14-1e21-4077-900e-4c7e69fad8a5" />
<img width="2000" height="1281" alt="Screenshot 2025-12-08 212649" src="https://github.com/user-attachments/assets/b633b03c-57e4-40c7-8b86-8839b3e9887f" />
<img width="2554" height="1374" alt="Screenshot 2025-12-09 062804" src="https://github.com/user-attachments/assets/61327dc0-ed76-4cb8-884e-4c668831ae3c" />
<img width="2553" height="1383" alt="Screenshot 2025-12-09 062834" src="https://github.com/user-attachments/assets/7b70c0b4-f0e9-4f49-94a3-69d4e4f941a2" />
<img width="2554" height="1382" alt="Screenshot 2025-12-09 062852" src="https://github.com/user-attachments/assets/1cc0e2dc-8d14-4fb8-9371-cee1acc4728b" />
<img width="945" height="1231" alt="Screenshot 2025-12-08 110235" src="https://github.com/user-attachments/assets/d0c4f591-3a6d-40ed-8343-e6a1f7fd40c1" />
<img width="934" height="999" alt="Screenshot 2025-12-08 110249" src="https://github.com/user-attachments/assets/5778c03c-5e96-4237-ac16-84f5858c0f3d" />
<img width="941" height="1249" alt="Screenshot 2025-12-08 110301" src="https://github.com/user-attachments/assets/fec2524d-28fa-409f-9bd6-0e5ec1e1ba18" />
<img width="942" height="1231" alt="Screenshot 2025-12-08 110313" src="https://github.com/user-attachments/assets/c7a5dab3-3554-4247-a884-b024198be98c" />
<img width="2547" height="1378" alt="Screenshot 2025-12-08 113345" src="https://github.com/user-attachments/assets/303fdaa3-8ec9-40e0-be92-dbe6f4ffc573" />
<img width="2558" height="1304" alt="Screenshot 2025-12-08 113731" src="https://github.com/user-attachments/assets/51e52d44-910f-417b-90ad-d46bfa58e358" />


 BUG LOG: V7 Fixes an issue previous versions had when attempting to run any code that required user input. Please continue reporting bugs as I greatly appreciate it<3!

### Requirements

```bash
pip install pygments jedi pillow
