# 🛡️ ScannerUSB — Analisador de Dispositivos de Memória

Aplicação de ambiente de trabalho para **Windows** que analisa pens, cartões de memória e discos externos à procura de malware, aproveitando o motor do **Microsoft Defender** já integrado no sistema operativo.

> Projeto desenvolvido em contexto académico.

---

## ✨ Funcionalidades

- Deteção automática dos dispositivos de memória ligados (USB, cartões, discos externos)
- Apresentação da etiqueta, tipo, espaço total e espaço livre de cada unidade
- Análise antimalware com o motor do **Microsoft Defender**
- Relatório da análise em tempo real, com veredito final (limpo / ameaças encontradas)
- Interface gráfica simples e intuitiva (Tkinter)

---

## ⚙️ Como funciona

Em vez de implementar um motor de deteção próprio — que seria ineficaz contra ameaças reais — a aplicação tira partido do **Microsoft Defender**, o antivírus já presente em todas as instalações modernas do Windows.

A deteção das unidades é feita através da API do Windows (`kernel32`), via `ctypes`, identificando o tipo de cada unidade (removível, fixa, etc.). Quando o utilizador escolhe um dispositivo, a aplicação invoca o motor do Defender:

```
MpCmdRun.exe -Scan -ScanType 3 -File <unidade>
```

O resultado é apresentado em tempo real e o código de saída do Defender é interpretado para indicar se foram ou não encontradas ameaças.

---

## 📋 Requisitos

- Windows 10 ou Windows 11
- Microsoft Defender ativo
- Python 3.10 ou superior *(apenas para correr a partir do código-fonte ou gerar o executável)*

> A aplicação **não usa bibliotecas externas** — apenas a biblioteca padrão do Python.

---

## ▶️ Executar a partir do código-fonte

```bash
python scanner_usb.py
```

---

## 🏗️ Gerar o executável (.exe)

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole --name ScannerUSB scanner_usb.py
```

O executável fica disponível em `dist/ScannerUSB.exe`.

---

## 🖱️ Utilização

1. Executar o programa **como administrador** (para a análise ter acesso total ao dispositivo)
2. Ligar a pen / cartão / disco externo
3. Clicar em **Atualizar lista** e selecionar a unidade pretendida
4. Clicar em **Analisar** e aguardar o relatório

---

## 📸 Capturas de ecrã

> _Adicionar aqui imagens da aplicação em funcionamento._

---

## ⚠️ Notas e limitações

- Funciona exclusivamente em Windows, por depender do Microsoft Defender.
- A análise de unidades grandes pode demorar vários minutos.
- O executável gerado pelo PyInstaller pode ser sinalizado como falso positivo por alguns antivírus.

---

## 🚧 Melhorias futuras

- [ ] Deteção e limpeza de atalhos maliciosos e ficheiros `autorun.inf`
- [ ] Gravação dos relatórios de análise em ficheiro
- [ ] Ejeção segura do dispositivo
- [ ] Formatação de unidades (com mecanismos de segurança)

---

## 📄 Licença

Distribuído sob a licença MIT. Ver o ficheiro [LICENSE](LICENSE) para mais detalhes.

---

## 👤 Autor

**Jaime** — projeto académico.
