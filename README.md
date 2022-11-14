# ISA – Síťové aplikace a správa sítí

Autor: Tomáš Bártů \
Login: xbartu11 \
Datum: 14.11.2022

## Generování NetFlow dat ze zachycené síťové komunikace

### Úvod

Cílem projektu do ISA – Síťové aplikace a správa sítí, bylo implementovat NetFlow exportér, který ze zachycených 
síťových dat, které jsou uloženy ve formě pcap souboru, vytvoří NetFlow záznamy, jenž jsou následně odeslány na cílový 
NetFlow kolektor.

### Schopnosti programu

Program podporuje pouze NetFlow verze 5, jinak by měl splňovat všechny body zadání. Při testování byla zjištěna občasná 
odlišnost v jednotlivých časech v řádech tisícin sekund, které mohou být způsobeny zaokrouhlováním při převodu jednotek.
Dále byly zjištěny občasné rozdíly v pořadí jednotlivých toků, ale celkové statistky bylo shodné. Důvodem může být
rozdílná implementace mého a testovacího programu.

### Příklady spouštění

Předpokládáme, že program spouštíme poprvé. Je ho tedy nutné nejdříve přeložít pomocí přiloženého Makefilu.

```bash
$ make
```

Přiložený Makefile disponuje i cílem clean, který vymaže vytvořené binární soubory.

```bash
$ make clean
```

Program je již přeložen. Lze ho tedy spustit. Je možné kombinovat jednotlivé argumenty. 
Avšak pokud se použijí argumenty opakovaně, tak se konečná hodnota bude rovnat hodnotě při posledním výskytu zadaného 
argumentu programu.

Zdrojová komunikace se nachází v souboru *file.pcap*.

```bash
$ ./flow -f file.pcap
```

IP adresa NetFlow kolektoru je *127.0.0.1*.
```bash
$ ./flow -c 127.0.0.1
```

Doménové jméno NetFlow kolektoru je *localhost*.
```bash
$ ./flow -c localhost
```

IP adresa kolektoru je *127.0.0.1* s cílovým číslem portu *4096*.
```bash
$ ./flow -c 127.0.0.1:4096
```

Doménové jméno NetFlow kolektoru je *localhost*  s cílovým číslem portu *4096*.
```bash
$ ./flow -c localhost:4096
```

Interval v sekundách, po kterém se mají aktivní NetFlow záznamy vyexportovat na kolektor, je *120*.
```bash
$ ./flow -a 120
```

Interval v sekundách, po kterém se mají neaktivní NetFlow záznamy vyexportovat na kolektor, je *5*.
```bash
$ ./flow -i 5
```

Velikost vyrovnávací paměti pro NetFlow záznamy (flow-cache) je *256* záznamů.
```bash
$ ./flow -m 256
```

### Jednotlivé přepínače
|      **Argumenty**      | **Popis**                                                                                                                               |
|:-----------------------:|-----------------------------------------------------------------------------------------------------------------------------------------|
|      -f \<soubor\>      | Jméno analyzovaného souboru nebo standardní vstup. Implicitní hodnota: STDIN.                                                           |
| -c <kolektor\:\<port\>> | IP adresa nebo doménové jméno NetFlow kolektoru. Volitelně i číslo portu. Implicitní hodnota: 127.0.0.1:2055.                           |
|  -a <aktivní časovač>   | Interval v sekundách, po kterém se exportují aktivní záznamy na kolektor Implicitní hodnota 60.                                         |
| -i <neaktivní časovač>  | Interval v sekundách, po jehož vypršení se exportují neaktivní záznamy na kolektor. Implicitní hodnota 10.                              |
|       -m <počet>        | Velikost flow-cache. Při dosažení maximální velikosti dojde k exportu nejstaršího záznamu v cachi na kolektor. Implicitní hodnota 1024. |

### Seznam souborů
* flow.cpp (.hpp)
* arguments.cpp (.hpp)
* pcap.cpp (.hpp)
* exporter.cpp (.hpp)
* Makefile
* README.md
* manual.pdf