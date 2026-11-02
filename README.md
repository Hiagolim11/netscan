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
4. Gera relatório em `relatorio.txt` e `relatorio.json` (com resumo por severidade) na pasta
   `resultados_<data>/`.

## Recursos de vulnerabilidade
- Scripts `vuln` (checagens conhecidas) + `vulners` (CVEs por versão de serviço).
- Classificação por severidade/CVSS e lista de CVEs por achado.
- Detecção de sistema operacional.
- Modo **profundo** (`--deep`): todas as 65535 portas (`-p-`) e scripts extras
  (`http-enum`, `http-headers`, `ssl-enum-ciphers`, `ssh2-enum-algos`, `default`).

## Robustez
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
```

## Empacotamento
```bash
npm run dist     # gera dist/netscan-<versão>.AppImage e dist/netscan-<versão>.deb
```
O `.deb` declara as dependências (`nmap`, `python3` + libs do Electron); instale com:
```bash
sudo apt install ./dist/netscan-1.0.0.deb
```

## Arquivos
- `netscan.py` — backend (descoberta, scan, severidade/CVE, relatório, `--json-stream`)
- `main.js` / `preload.js` — processo Electron (spawn do backend, IPC, diálogo de senha sudo)
- `renderer/` — interface (`index.html`, `styles.css`, `renderer.js`)
- `build/icon.png` — ícone do app
