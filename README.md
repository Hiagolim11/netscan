# netscan

Varredura de rede com **descoberta de dispositivos** e **checagem de vulnerabilidades**, com CLI
e interface desktop (Electron). Baseada em `nmap`.

> ⚠️ Use **somente** em redes que você possui ou tem autorização explícita para testar.

## Como funciona
1. Descobre hosts ativos na rede (ping/ARP scan — `nmap -sn -PR`).
2. Em cada host vivo:
   - detecta portas e serviços (`-sV`);
   - detecta o sistema operacional (`-O`, quando root);
   - roda os scripts de vulnerabilidade do nmap (`--script vuln,vulners`) — `vulners` mapeia
     **CVEs a partir da versão do serviço** (requer internet).
3. Classifica cada achado por **severidade** a partir do CVSS
   (crítica ≥ 9, alta ≥ 7, média ≥ 4, baixa > 0) e extrai os **CVEs**.
4. Gera relatório em `relatorio.txt`, `relatorio.html`, `relatorio.csv` e `relatorio.json` (com resumo por severidade) na pasta
   `resultados_<data>/`.

## Recursos de vulnerabilidade
- Scripts `vuln` (checagens conhecidas) + `vulners` (CVEs por versão de serviço).
- Classificação por severidade/CVSS e lista de CVEs por achado.
- Detecção de sistema operacional.
- Modo **profundo** (`--deep`): todas as 65535 portas (`-p-`) e scripts extras
  (`http-enum`, `http-headers`, `ssl-enum-ciphers`, `ssh2-enum-algos`, `default`).

## Exploits e configuração
- **Exploits públicos**: cada serviço com produto + versão é cruzado com o Exploit-DB local
  (`searchsploit`, já vem no Kali; funciona offline). DoS é ignorado. Confirme a versão antes de concluir.
- **Checagens de configuração** (só leitura, sem testar senhas): FTP anônimo, SMB sem assinatura
  ou com convidado, TLS fraco (nota C–F), certificado expirado, SNMP com community padrão.

## Correção e IPv6
- Cada achado traz uma **dica de correção** (na interface e nos relatórios TXT/HTML/CSV).
- Serviços em texto puro (Telnet, rlogin/rsh, FTP, TFTP) viram achados.
- `--ipv6` (alvo vazio): acha vizinhos IPv6 por multicast, junta ao mesmo aparelho IPv4 pelo MAC
  e procura **portas abertas só via IPv6** (firewall IPv4 que não cobre o IPv6). Alvos IPv6
  também podem ser passados direto em `-t`.

## Mais opções
- Vários alvos (`-t "10.0.0.0/24, 192.168.1.5"`); sem alvo, varre **todas** as sub-redes locais.
- `-p` portas escolhidas, `-x` exclusões, `--udp` portas UDP comuns (root), `--no-ping` (-Pn).
- `-w N` analisa N hosts em paralelo; `--host-timeout` ajustável.
- `--compare relatorio.json`: mostra hosts novos/sumidos, portas abertas/fechadas e vulns novas/corrigidas.

## Robustez
- Parar a varredura encerra todos os nmap em paralelo e impede que hosts na fila iniciem.
- Falha ao analisar um host não derruba a varredura inteira.
- Encerramento limpo: ao parar, o processo `nmap` filho é terminado (signal handler + kill do grupo).
- `--host-timeout` para que um host travado não paralise a varredura.
- Validação do alvo e tratamento de erros (XML parcial, nmap/sudo/python ausentes).
- Resultados parciais são aproveitados mesmo se o nmap retornar código de erro.

## Pré-requisitos
- `nmap`, `python3` (já presentes no Kali)
- Para a interface: `node` + `npm` (Electron é instalado localmente)
- `sudo` recomendado (ARP scan, detecção de SO e vários scripts exigem root)

## Interface (Electron)
```bash
cd netscan
npm install          # se o binário do electron não baixar, rode: node node_modules/electron/install.js
npm start
```
Na janela: informe o alvo (ou deixe vazio para auto-detectar a sub-rede), escolha as opções
("Rápido", "Profunda", "sudo") e clique em **Iniciar varredura**. Os dispositivos aparecem um a um;
clique num dispositivo para ver portas, SO e vulnerabilidades (com badge de severidade e CVEs).

Em **Opções avançadas**: portas, exclusões, paralelismo, UDP, sem ping e comparação automática
com a varredura anterior (dispositivos marcados como *novo* / *mudou*). Acima da lista há filtro
por texto (IP, nome, serviço, CVE) e "só com vulnerabilidades". Cada dispositivo tem ações:
**Re-escanear** só ele, **Copiar IP**, **Copiar JSON**, **Abrir http(s)** nas portas web e
links para os exploits no Exploit-DB. Também dá para dar um **apelido/nota** (salvo por MAC, só nesta máquina).

- **Progresso** de cada host (fase do nmap, %, tempo restante) enquanto ele é varrido.
- **Histórico**: lista as varreduras salvas; clique para reabrir. Em "Comparar com" escolha qualquer uma.
- **Monitoramento**: "Repetir a cada (min)" refaz a varredura e mostra notificação quando aparece
  dispositivo ou vulnerabilidade nova. Se o sudo pedir senha, ela fica **só em memória** enquanto o
  monitoramento estiver ativo e é descartada ao clicar em Parar. O app precisa ficar aberto.
- Re-escanear um host salva em `rescan_<data>/`, que não entra no histórico nem na comparação.

### Senha do sudo
Se a opção **sudo** estiver marcada e o sistema exigir senha, o app abre uma **caixa de diálogo**
pedindo a senha. Ela é usada apenas para autenticar o sudo (`sudo -v`, que cacheia a credencial);
a varredura roda com `sudo -n` e **a senha nunca é gravada, registrada nem passada ao processo de scan**.
Se o sudo já for sem senha (sudoers), o diálogo não aparece.

## CLI
```bash
sudo python3 netscan.py                      # auto-detecta a sub-rede local
sudo python3 netscan.py -t 192.168.0.0/24    # alvo explícito (CIDR)
sudo python3 netscan.py -t 192.168.0.10      # um único host
sudo python3 netscan.py --deep               # todas as portas + scripts extras (lento)
python3 netscan.py --fast                    # só descoberta + serviços, sem scripts vuln
python3 netscan.py --json-stream             # emite eventos JSON (usado pela interface)
sudo python3 netscan.py -w 4 -p 1-1024 --udp -x 192.168.0.1
sudo python3 netscan.py --compare resultados_<data>/relatorio.json
python3 -m unittest test_netscan              # testes da lógica pura
```

## Empacotamento
```bash
npm run dist     # gera dist/netscan-<versão>.AppImage e dist/netscan-<versão>.deb
```
O `.deb` declara as dependências (`nmap`, `python3` + libs do Electron); instale com:
```bash
sudo apt install ./dist/netscan-1.1.0.deb
```

## Arquivos
- `netscan.py` — backend (descoberta, scan, severidade/CVE, relatório, `--json-stream`)
- `main.js` / `preload.js` — processo Electron (spawn do backend, IPC, diálogo de senha sudo)
- `renderer/` — interface (`index.html`, `styles.css`, `renderer.js`)
- `build/icon.png` — ícone do app
