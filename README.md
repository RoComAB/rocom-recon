# RoCom Recon

Lättviktig, icke-exploaterande nätverksinventering för RoCom Cyber Probe. Lösningen gör discovery, tjänsteidentifiering och CSV/XML-export. Den kör inte brute force, exploit eller DoS.

## Funktioner

- Hämtar primär IPv4-adress automatiskt
- Skannar motsvarande privata `/24`-nät som standard
- ARP discovery med Nmap
- Tjänste- och versionsidentifiering på de 200 vanligaste TCP-portarna
- En samlad CSV-rad per enhet
- Sparar rå XML, läsbar Nmap-text och `latest-*`-filer
- Avvisar publika nät och nät större än `/24`

## Krav

- Docker med host networking
- Linux-baserad värd
- `NET_RAW` och `NET_ADMIN`
- Enbart nät där RoCom har uttryckligt tillstånd att inventera

## Lokal körning

```bash
docker compose build
docker compose run --rm recon
```

Resultat hamnar i `./output`.

## Inställningar

Redigera `docker-compose.yml` eller skapa `.env` från `.env.example`.

- `FORCE_PREFIX=24`: använd lokalt IP men tvinga `/24`
- `TARGET_NETWORK=`: valfritt explicit privat nät, exempel `10.10.20.0/24`
- `TOP_PORTS=200`: antal vanligaste TCP-portar
- `EXCLUDE_IPS=`: kommaseparerade adresser som ska hoppas över
- `NMAP_TIMING=T3`: försiktig normal timing

## Teltonika RUTC50

Installera Docker från RutOS Package Manager. Använd USB-baserad lagring för images, loggar och output när möjligt. Containern ska använda host networking för att ARP discovery ska fungera på lokalt LAN.

## GitHub Container Registry

Byt `CHANGE_ME` i `docker-compose.yml` till ditt GitHub-konto eller din organisation. Workflow-filen bygger en multi-architecture-image och publicerar den till GHCR när du pushar till `main` eller skapar en tagg.

## Säkerhetsgränser

Recon är byggd för inventering, inte intrångstestning. Aktiv validering, autentiseringstest och exploatering ska hanteras i ett separat, godkänt pentestflöde med exakt scope och testfönster.
