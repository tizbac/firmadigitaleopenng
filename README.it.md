# Informazioni

Per essere chiari: questo progetto è in gran parte "vibe-coded", dal progetto
Python originale che ho creato; se non ti sta bene, sentiti libero di usare
quelli instabili che a malapena funzionano su Linux o richiedono Ubuntu 8.04 :)
Le firme risultanti sono state verificate con lo strumento di verifica
Infocert e superano completamente i controlli.

Attenzione: per alcuni lettori di smart card potresti aver bisogno non solo di
OpenSC ma anche dei driver ccid.

# FirmaDigitaleOpen C++

> Versione italiana — [English version](README.md)

Riscrittura in C++/Qt6 dello strumento Python `FirmaDigitaleOpen`. Firma PDF con
**PAdES-BES** e produce/verifica firme **P7M** (CMS detached), usando un token
di sicurezza PKCS#11 (Bit4id) per la chiave privata. Verifica inoltre le liste
di fiducia **TSL** (Trusted Lists / liste di fiducia italiane ed europee).

Il nucleo crittografico (`fdo_core`) non ha dipendenze Qt ed è completamente
testato; la GUI Qt si appoggia su di esso.

## Funzionalità

- **PAdES-BES** firma digitale di PDF (ByteRange + CMS signed-data, attributi
  firmati in stile RFC 3161, ritaggiati secondo il layout della specifica PDF).
- **P7M** firma e verifica di CMS detached.
- **TSL** parser + verificatore di liste di fiducia (Trusted Lists italiane/Ue).
- **Build Windows x64** (cross-compilazione MinGW in Docker) con installer NSIS
  autoconsistente che include Qt, poppler, OpenSSL e il modulo PKCS#11 Bit4id.

## Modello di fiducia

La verifica delle firme si basa esclusivamente sulla TSL e fallisce in modo
sicuro. Le ancore di fiducia sono i certificati CA dei servizi attualmente
`granted`, `recognisedatnationallevel` o `accredited` nella TSL selezionata o
in cache. Il certificato della firma XML della TSL (`ds:KeyInfo`), i servizi
ritirati/cessati e i servizi non-CA (TSA, eSeal, identità) non vengono mai usati
come ancore. Senza una TSL aggiornata — file esplicito, cache fresca o download
automatico riuscito — nessun PDF/P7M firmato viene dichiarato valido. Il
verificatore del core rifiuta inoltre un insieme di ancore vuoto prima di
validare la catena, quindi non esiste alcun fallback auto-fidato.
- **PKCS#11** strato per token: wrapper `dlopen`/`LoadLibraryW` minimale (senza
  header PKCS#11 di sistema) che enumera gli slot, esegue il login, trova la
  chiave/certificato del firmatario tramite `CKA_ID "DS3"` e firma.
- Helper per XML canonico (C14N).

## Dipendenze

- CMake >= 3.16, un compilatore C++17 (g++/clang)
- Qt 6.5+ (Widgets, Network, Sql)
- OpenSSL 3.x
- libxml2
- Per il test con *emulatore* PKCS#11 (opzionale): SoftHSM2 (`softhsm2-util`),
  OpenSC (`pkcs11-tool`) e `openssl`

Debian/Ubuntu:
```
sudo apt install qt6-base-dev libssl-dev libxml2-dev cmake g++ \
     softhsm2 opensc openssl
```

## Compilazione

```
cmake -S . -B build
cmake --build build -j
```

Output:
- `build/firmadigitaleopen` — la GUI Qt
- `build/fdo_core` — la libreria crittografica/PKCS#11 statica
- `build/tst_*` — gli eseguibili di test

## Build Windows (64 bit)

La GUI Windows viene cross-compilata con MinGW-w64 in Docker e impacchettata
con un installer NSIS nativo. Il risultato è un'applicazione x64
autoconsistente: Qt, poppler, OpenSSL, libxml2 e il runtime MinGW sono inclusi,
quindi sulla macchina di destinazione non serve installare nulla.

```bash
docker build --target win-package -t fdo-win .
docker run --rm -v "$PWD:/out" fdo-win
# -> firmadigitaleopen-<version>-win64-setup.exe
```

Cosa fanno gli stage Docker:

- I pacchetti Fedora 44 `mingw64-*` forniscono toolchain, Qt 6.11,
  poppler-qt6, OpenSSL 3 e libxml2; `cmake/toolchain-mingw64.cmake` indica a
  CMake quello sysroot.
- `packaging/windows/deploy.sh` analizza le tabelle di import PE
  dell'eseguibile e dei plugin, copia accanto all'eseguibile ogni DLL non di
  sistema presente nello sysroot e i plugin Qt necessari (`platforms`,
  `styles`, `tls`, `sqldrivers`, `networkinformation`) — lo stesso risultato di
  `windeployqt`, che la Qt cross di Fedora non fornisce.
- Uno stage Debian esegue `makensis` (NSIS nativo per Linux, senza Wine) su
  `packaging/windows/installer.nsi`.

L'installer installa in `%ProgramFiles%\FirmaDigitaleOpen`, crea i collegamenti
nel menu Start e sul desktop, registra `.pdf` in *Apri con* e associa `.p7m`
quando non ha già un proprietario, e include il disinstallatore. L'eseguibile è
una GUI (`-mwindows`) con icona e risorsa VERSIONINFO.

Il modulo PKCS#11 Bit4id è incluso: `bit4xpki.dll` è il modulo ufficiale
**x86-64** di Bit4id estratto dal kit Universal Middleware (versione modulo
1.4.11.1228, installer 11.861), insieme a `bit4xpki.dll.conf` e
`bit4xpki.dll.rc/*.lic`. Questi file devono sempre stare nella stessa directory
dell'eseguibile (il modulo li legge da lì). Se il modulo manca la compilazione
riesce comunque e, a runtime, l'app ripiega su un'installazione Bit4id a
livello di sistema (`%SystemRoot%\System32\bit4xpki.dll`) oppure su OpenSC.

Per ora i test Windows non vengono eseguiti: le suite ctest sono solo POSIX e
gestite da `tests/run_pkcs11.sh`; la build Windows è verificata a livello di
compilazione dal workflow GitHub Actions `windows`.

L'installer e l'eseguibile non sono firmati digitalmente, quindi al primo avvio
Windows SmartScreen potrebbe mostrare un avviso.

## Esecuzione dei test

```
ctest --test-dir build --output-on-failure
```

Suite: `c14n`, `tslverifier`, `p7mverify`, `pades`, `pkcs11`, `guisign`.
Le prime quattro sono pure e non richiedono hardware. `guisign` costruisce la
`MainWindow` Qt offscreen, renderizza una pagina PDF tramite Poppler
(`PdfPreview`) e — quando un token è raggiungibile — esegue esattamente il
percorso token→certificato→firma PAdES/P7M che la GUI usa (headless, nessun
display richiesto). Le suite `pkcs11` e `guisign` sono gestite da
[`tests/run_pkcs11.sh`](tests/run_pkcs11.sh), che seleziona automaticamente un
modulo:

1. **Token fisico** — se sono impostate `FDO_PKCS11_LIB` (e opzionalmente
   `FDO_PKCS11_PIN`), viene usato quel modulo. Esempio (Bit4id):
   ```
   FDO_PKCS11_LIB=../libbit4xpki.so FDO_PKCS11_PIN=1234 \
       ctest --test-dir build -R pkcs11 --output-on-failure
   ```
2. **Emulatore SoftHSM** — altrimenti, se SoftHSM2 è installato, viene
   inizializzato un token usa-e-getta in una directory temporanea, vengono
   importati una nuova chiave RSA + un certificato autofirmato (con
   `CKA_ID "DS3"`), e viene esercitato l'intero percorso **login →
   findSigner → firma → verifica**. La firma viene verificata rispetto al
   certificato del token con codice OpenSSL EVP indipendente, quindi un
   percorso di firma sbagliato fa fallire il test.
3. **Fallback** — se non è disponibile nulla, per un test di sola
   enumerazione viene caricata la libreria Bit4id presente nell'albero dei
   sorgenti. Un token mancante non è mai un errore fatale; lo sono invece un
   errore di caricamento/ABI della libreria o una verifica di firma non
   corrispondente.

Si può anche eseguire il binario di test PKCS#11 direttamente contro
l'emulatore:
```
SOFTHSM2_CONF=/path/to/softhsm2.conf \
    ./build/tst_pkcs11 /usr/lib/softhsm/libsofthsm2.so <user-pin>
```

## Emulatore PKCS#11 (SoftHSM2)

Per sviluppare o testare non serve un token fisico. SoftHSM2 fornisce un token
PKCS#11 software. Il test `pkcs11` (ctest) ne configura uno automaticamente in
una directory temporanea e lo smantella alla fine. Per configurarne uno **a
mano** (es. per ispezionarlo con `pkcs11-tool` o per puntarvi la GUI):

```bash
# 1) Area di lavoro + config
export FDO_SHSM=/tmp/fdo-softhsm
mkdir -p "$FDO_SHSM/tokens"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\n' \
    "$FDO_SHSM" > "$FDO_SHSM/softhsm2.conf"
export SOFTHSM2_CONF="$FDO_SHSM/softhsm2.conf"          # ogni client PKCS#11 ne ha bisogno

LIB=/usr/lib/softhsm/libsofthsm2.so        # adatta al tuo percorso di installazione
PIN=12345678

# 2) Inizializza un token (imposta sia i PIN SO che utente)
softhsm2-util --init-token --free --label "FDO Test Token" \
    --so-pin "$PIN" --pin "$PIN"

# 3) Genera una chiave RSA + un certificato autofirmato
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$FDO_SHSM/key.pem" -out "$FDO_SHSM/cert.pem" \
    -subj "/CN=FDO SoftHSM Test User"

# 4) Importa certificato + chiave privata, entrambi con CKA_ID "DS3" (0x445333) —
#    l'id che il flusso di firma Bit4id cerca per primo.
pkcs11-tool --module "$LIB" --write-object "$FDO_SHSM/cert.pem" \
    --type cert    --id 44:53:33 --label "DS3 cert" --pin "$PIN"
pkcs11-tool --module "$LIB" --write-object "$FDO_SHSM/key.pem" \
    --type privkey --id 44:53:33 --label "DS3 key"  --pin "$PIN"

# 5) Verifica
pkcs11-tool --module "$LIB" --list-objects --pin "$PIN"
```

Poi esegui il test puntando ad esso:
```
SOFTHSM2_CONF="$FDO_SHSM/softhsm2.conf" \
    ./build/tst_pkcs11 "$LIB" "$PIN"
```
L'output atteso termina con:
```
  sign OK: 256 bytes
  verify OK: signature matches certificate
```

### Note / insidie dell'emulatore

- **`SOFTHSM2_CONF` deve essere esportata** per ogni processo che carica il
  modulo SoftHSM, altrimenti viene usata la directory dei token di default di
  sistema.
- **L'importazione della chiave privata richiede un login utente** (`--pin`),
  non un login SO (`--so-pin`).
- SoftHSM riporta tutti i suoi slot virtuali come `tokenPresent`, quindi lo
  strato distingue i token reali cercando un certificato sullo slot.
- La `C_FindObjects` di SoftHSM richiede un `pObjectCount` **non-NULL**.
- SoftHSM **non** espone `CKA_ID` in lettura (il probe di lunghezza restituisce
  `CK_UNAVAILABLE_INFORMATION`). La ricerca `CKA_ID "DS3"` dello strato quindi
  non trova corrispondenze e ripiega in modo trasparente su una ricerca per
  sola classe. Ciò è corretto per un token con una sola chiave; su un token
  reale che espone `CKA_ID` (es. Bit4id), la selezione basata sull'id viene
  usata per scegliere la chiave giusta.
- **Disallineamento dell'id del meccanismo:** l'header `p11-kit` di questo
  sistema e la sua build di SoftHSM codificano `CKM_SHA256_RSA_PKCS` come
  `0x40`, mentre la specifica OASIS (e la maggior parte dei token, es. Bit4id)
  usa `0x1051`. Lo strato PKCS#11 in `src/pkcs11.cpp` prova quindi entrambi i
  valori in `sign()` per funzionare con entrambe le codifiche.

## Struttura del progetto

```
src/
  pkcs11_abi.h    ABI PKCS#11 minimale (tipi, costanti, puntatori a funzioni)
  pkcs11.{h,cpp}  wrapper dlopen PKCS#11 (slot, login, firmatario, firma)
  cmssigner.{h,cpp} costruzione + verifica CMS (signed-data)
  pades.{h,cpp}   firma PAdES-BES dei PDF (layout ByteRange)
  p7m.{h,cpp}     firma/verifica P7M (CMS detached)
  der.{h,cpp}     helper di codifica/decodifica DER
  c14n.{h,cpp}    XML canonico
  tslparser / tslverifier  parsing + verifica TSL
  x509util.{h,cpp} helper X.509
  base64.{h,cpp}
   main.cpp / mainwindow.*  GUI Qt (tab PAdES + P7M)
   pdfpreview.*             vista pagina PDF Poppler + riquadro firma
tests/
   tst_c14n.cpp / tst_tslverifier.cpp / tst_p7mverify.cpp / tst_pades.cpp
   tst_pkcs11.cpp + run_pkcs11.sh   test PKCS#11 + selezione automatica del modulo
   tst_guisign.cpp                  test headless della GUI + percorso di firma
   data/                            fixture (TSL, PDF di esempio, ecc.)
cmake/toolchain-mingw64.cmake        toolchain cross Windows x64 (Fedora mingw64)
packaging/windows/                   installer NSIS + deploy delle DLL runtime
```

## Stato

- Nucleo crittografico/PKCS#11: **completo** e coperto dalle suite di test.
- GUI: **completa** — tab PAdES / P7M con rilevamento slot e anteprima PDF
  (riquadro di firma cliccabile), collegata al core `Pkcs11` + `Pades`/`P7M`.
  Coperta headless dalla suite `guisign` (costruzione offscreen, render
  Poppler, percorso completo token→firma→verifica). Layout visivo non ancora
  revisionato.