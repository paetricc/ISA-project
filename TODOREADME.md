# ISA - Síťové aplikace a správa sítí

Autor: Tomáš Bártů \
Login: xbartu11

## Varianta ZETA – Sniffer paketů

### Úvod

Úkolem projektu bylo vytvořit v síťový analyzátor, který dle zadaných parametrů bude moci filtrovat {rámce, pakety,
datagramy, segmenty} a vypsat zajímavé údaje, které obsahují. Například zdrojovou nebo cílovou Media Access Control
adresu, zkráceně MAC adresu. Či vypsat zdrojový a cílový port protokolu TCP. Dalším úkolem bylo vypsat payload v bajtové
podobě tak i ve znakové.

### Schopnosti programu

Program by měl umožňovat vše, co bylo požadováno v zadání. Nad rámce zadání program vypisuje při přepínači --arp data
navíc a to informace obsažené v datové části paketu a to zdrojovou MAC adresu a zdrojovou IP adresu odesílatele plus (v
případě žádosti) MAC adresu ff:ff:ff:ff:ff:ff a IP adresu hledaného.

### Příklad spuštění

Předpokládáme, že program spouštíme poprvé. Je ho tedy nutné nejdříve přeložít pomocí přiloženého Makefilu.

```
$ make
```

Přiložený Makefile disponuje i cílem clean, který vymaže vytvořené binární soubory

```
$ make clean
```

Po provedení prvního příkazu máme přeložený program, takže ho můžeme spustit. Program je třeba spustit pod rootovským
opravněním.

```
$ sudo ./packetsniffer -i
enp0s3
lo
any
bluetooth-monitor
nflog
nfqueue
```

Nyní si budeme chtít například odchytit ICMP protokol. Použijeme tedy následující příkaz.

```
$ sudo ./packetsniffer -i lo --icmp
timestamp: 2022-04-24T21:08:13.654516+0200
src MAC: 00:00:00:00:00:00
dst MAC: 00:00:00:00:00:00
frame length: 98 bytes
src IP: 127.0.0.1
dest IP: 127.0.0.1

0x0010  00 00 00 00 00 00 00 00  00 00 00 00 08 00 45 00     ........ ......E.
0x0020  00 54 23 b1 40 00 40 01  18 f6 7f 00 00 01 7f 00     .T#.@.@. ........
0x0030  00 01 08 00 1f 2c 00 01  00 01 1d a0 65 62 00 00     .....,.. ....eb..
0x0040  00 00 8d fc 09 00 00 00  00 00 10 11 12 13 14 15     ........ ........
0x0050  16 17 18 19 1a 1b 1c 1d  1e 1f 20 21 22 23 24 25     ........ .. !"#$%
0x0060  26 27 28 29 2a 2b 2c 2d  2e 2f 30 31 32 33 34 35     &'()*+,- ./012345
0x0070  36 37                                                67
```
Na výstupu si můžeme povšimnout například délky rámce v bytech či timestampu.

### Jednotlivé přepínače
* --interface či -i – zobrazí seznam dostupných zařízení
* --port či -p – bude filtrovat dle zadaného čísla portu
* --tcp či -t – bude filtrovat pouze TCP protokol
* --udp či -u – bude filtrovat pouze UDP protokol
* --icmp či -I – bude filtrovat pouze ICMP protokol
* --arp či -a – bude filtrovat pouze ARP protokol
* --number či -n – zobrazí a zachytí informace tolikrát, koliktrát o ně bylo požádáno

### Seznam souborů
* packetsniffer.c
* packetsniffer.h
* Makefile
* README.md
* manual.pdf