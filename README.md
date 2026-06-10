# DNS-SPOOFING

> **Autor:** Randy Nin  **Laboratorio de Seguridad de Redes | GNS3**

Script de Python que realiza un ataque de DNS Spoofing combinando ARP Spoofing bidireccional y falsificación de respuestas DNS. Se posiciona como intermediario del tráfico entre la víctima y el gateway, intercepta cada consulta DNS para el dominio objetivo e inyecta una respuesta forjada apuntando a un servidor web controlado por el atacante, redirigiendo la navegación de la víctima de forma completamente transparente.

---

## Contenido del repositorio

```
DNS-SPOOFING/
├── dns_spoofing.py
├── Documentación Tecnica Profesional DNS-SPOOFING MITM (Randy Nin -- 2025-0660).pdf
└── README.md
```

---

## Documentación técnica

La documentación técnica completa de este laboratorio está disponible en:

**[Documentación Tecnica Profesional DNS-SPOOFING MITM (Randy Nin -- 2025-0660).pdf](Documentación%20Tecnica%20Profesional%20DNS-SPOOFING%20MITM%20(Randy%20Nin%20--%202025-0660).pdf)**

Incluye contexto técnico de DNS y ARP Spoofing, topología y configuración del entorno con servidor web Docker, análisis técnico completo del script, evidencia del ataque con capturas de pantalla y contramedidas con DHCP Snooping y Dynamic ARP Inspection.

---

## Requisitos

**Sistema:** ParrotSec OS, Kali Linux o cualquier distribución Linux con soporte para envío de paquetes raw y sniffing de tráfico.

**Python:** 3.x con permisos de superusuario (`sudo`).

**Dependencias externas:**

|Librería|Instalación|
|:--|:--|
|`scapy`|`pip install scapy`|
|`termcolor`|`pip install termcolor`|
|`pwntools`|`pip install pwntools`|

**Instalación rápida:**

```bash
pip install scapy termcolor pwntools
```

**IP Forwarding requerido** para que el MitM sea transparente:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

---

## Uso

```bash
sudo python3 dns_spoofing.py -i <interfaz> -t <IP_víctima> -g <IP_gateway> -d <dominio> -a <IP_falsa>
```

**Parámetros:**

|Flag|Descripción|Default|
|:--|:--|:-:|
|`-i` / `--interface`|Interfaz de red del atacante|Requerido|
|`-t` / `--target`|IP de la víctima|Requerido|
|`-g` / `--gateway`|IP del gateway|Requerido|
|`-d` / `--domain`|Dominio a suplantar|`itla.edu.do`|
|`-a` / `--address`|IP falsa entregada como respuesta DNS|IP del atacante|

**Ejemplo usado en el laboratorio:**

```bash
sudo python3 dns_spoofing.py -i ens4 -t 25.6.60.21 -g 25.6.60.1 -d itla.edu.do -a 25.6.60.23
```

Presionar `Ctrl+C` para detener el ataque. El script restaura automáticamente las tablas ARP de la víctima y el gateway antes de cerrar.

---

## Cómo funciona

El script opera en dos capas simultáneas ejecutadas en hilos independientes:

**Capa 1: ARP Spoofing (hilo daemon)**

Cada 2 segundos envía dos ARP replies falsificados:

|Dirección|ARP reply falsificado|
|:--|:--|
|Hacia víctima (25.6.60.21)|"La IP del gateway 25.6.60.1 está en mi MAC"|
|Hacia gateway (25.6.60.1)|"La IP de la víctima 25.6.60.21 está en mi MAC"|

**Capa 2: DNS Spoofing (hilo principal)**

Monitorea el tráfico UDP en puerto 53. Por cada consulta DNS que coincida con el dominio objetivo:

1. Extrae el ID de transacción y el nombre consultado de la query original
2. Construye una respuesta DNS forjada con la IP del servidor web malicioso como registro A
3. La envía directamente al cliente antes de que llegue la respuesta legítima

```
IP (dst=víctima, src=8.8.8.8) / UDP (dport=query_port, sport=53)
  └── DNS (qr=1, aa=1, ra=1, id=original)
        └── DNSRR (rrname=itla.edu.do, ttl=3600, rdata=25.6.60.23)
```

---

## Entorno de laboratorio

|Dispositivo|Rol|IP|MAC|
|:--|:--|:--|:--|
|R-1|Gateway / DHCP / NAT|25.6.60.1/25|0c:cf:73:07:00:00|
|Kali Linux|Víctima|25.6.60.21/25|0c:b2:03:00:00:00|
|WEB-SERVER (Docker)|Servidor web falso|25.6.60.23/25|02:42:43:61:6d:00|
|ParrotSec|Atacante|25.6.60.24/25|N/A|

> Red de laboratorio: 25.6.60.0/25 (VLAN 1). DNS configurado en la víctima: 8.8.8.8.

---

## Impacto observado

- Tablas ARP de la víctima y el gateway envenenadas con la MAC del atacante
- Todo el tráfico entre la víctima e internet transita por el atacante de forma transparente
- Consultas DNS para itla.edu.do interceptadas y respondidas con la IP del servidor Docker
- La víctima ve la página falsa del atacante bajo la URL itla.edu.do sin ninguna alerta visible (HTTP)

---

## Mitigación

DHCP Snooping + Dynamic ARP Inspection (DAI) en el switch del atacante (Sw-3):

```
Sw-3(config)# ip dhcp snooping
Sw-3(config)# ip dhcp snooping vlan 1
Sw-3(config)# ip arp inspection vlan 1
Sw-3(config)# interface range GigabitEthernet0/1-2
Sw-3(config-if-range)# ip dhcp snooping trust
Sw-3(config-if-range)# ip arp inspection trust
```

DAI valida cada ARP reply contra la binding table construida por DHCP Snooping. Los replies falsificados del atacante son descartados al no coincidir con la tabla, el MitM no puede establecerse y la cadena completa del ataque se rompe desde su fundamento. El script falla en la resolución de MACs antes de poder enviar un solo paquete DNS falsificado.

---

## Video demostrativo

**Enlace:** [https://www.youtube.com/watch?v=FV49LuGZuQk&list=PLxMefEiS_P6qxDUldXrtZpiMe3V1EW5yi](https://www.youtube.com/watch?v=FV49LuGZuQk&list=PLxMefEiS_P6qxDUldXrtZpiMe3V1EW5yi)

---

## Disclaimer

Este script fue desarrollado con fines exclusivamente académicos y educativos. Su uso está permitido únicamente en entornos propios o autorizados como GNS3, EVE-NG o laboratorios internos de prueba. El uso en redes de terceros sin autorización expresa constituye una violación legal.

---

_Randy Nin / Matrícula 2025-0660_

---
