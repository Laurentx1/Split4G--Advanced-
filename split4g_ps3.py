import os
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import time
import logging
from datetime import timedelta
import threading
import hashlib
import json

# ===== CONFIGURAÇÕES GLOBAIS =====
LIMITE_FAT32 = 4 * 1024**3 - 100 * 1024**2  # 3.9GB (margem maior de segurança)
LOG_FILE = "split4g_ps3.log"
TAMANHO_BUFFER = 1024 * 1024 * 64  # 64MB (melhor performance)
CONFIG_FILE = "split4g_config.json"

# ===== CONFIGURAÇÃO DO LOG =====
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%d/%m/%Y %H:%M:%S',
    encoding='utf-8'
)

class Split4GApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Split4G PS3 - Copiador de Jogos v6.0 Enhanced")
        self.root.geometry("700x550")
        self.root.resizable(True, False)
        
        # Configuração de estilo
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', font=('Segoe UI', 10))
        self.style.configure('TLabel', font=('Segoe UI', 9))
        self.style.configure('red.TButton', foreground='red', font=('Segoe UI', 10, 'bold'))
        self.style.configure('green.TButton', foreground='green', font=('Segoe UI', 10, 'bold'))
        
        # Variáveis de controle
        self.origem = Path(".")
        self.destino = Path(".")
        self.copiar_ativo = False
        self.cancelar_copia = False
        self.pausar_copia = False
        self.estatisticas = {
            'arquivos_copiados': 0,
            'bytes_copiados': 0,
            'arquivos_divididos': 0,
            'tempo_inicio': 0
        }
        
        # Carrega configurações salvas
        self.carregar_config()
        
        # Interface
        self.criar_interface()
        
        # Protocolo de fechamento
        self.root.protocol("WM_DELETE_WINDOW", self.ao_fechar)
    
    def carregar_config(self):
        """Carrega configurações salvas"""
        try:
            if Path(CONFIG_FILE).exists():
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.origem = Path(config.get('origem', '.'))
                    self.destino = Path(config.get('destino', '.'))
        except Exception as e:
            logging.warning(f"Erro ao carregar configurações: {e}")
    
    def salvar_config(self):
        """Salva configurações atuais"""
        try:
            config = {
                'origem': str(self.origem),
                'destino': str(self.destino)
            }
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.warning(f"Erro ao salvar configurações: {e}")
    
    def criar_interface(self):
        # Frame principal com scrollbar
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título melhorado
        titulo_frame = ttk.Frame(main_frame)
        titulo_frame.grid(row=0, column=0, columnspan=3, pady=(0, 15), sticky="ew")
        
        ttk.Label(
            titulo_frame,
            text="🎮 SPLIT4G PS3 - COPIADOR DE JOGOS ENHANCED",
            font=("Segoe UI", 16, "bold"),
            foreground="#2c3e50"
        ).pack()
        
        ttk.Label(
            titulo_frame,
            text="Copia jogos PS3 para FAT32 com divisão automática de arquivos >3.9GB",
            font=("Segoe UI", 10),
            foreground="#7f8c8d"
        ).pack()
        
        # Frame de configurações aprimorado
        config_frame = ttk.LabelFrame(main_frame, text=" 📁 Configurações de Pasta ", padding=15)
        config_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=10)
        
        # Origem
        ttk.Label(config_frame, text="Pasta de Origem (Jogos PS3):").grid(row=0, column=0, sticky="w", pady=5)
        self.origem_entry = ttk.Entry(config_frame, width=60)
        self.origem_entry.grid(row=0, column=1, padx=10, sticky="ew")
        self.origem_entry.insert(0, str(self.origem))
        ttk.Button(
            config_frame,
            text="📂 Procurar",
            command=self.selecionar_origem,
            width=12
        ).grid(row=0, column=2, padx=5)
        
        # Destino
        ttk.Label(config_frame, text="Pasta de Destino (FAT32):").grid(row=1, column=0, sticky="w", pady=5)
        self.destino_entry = ttk.Entry(config_frame, width=60)
        self.destino_entry.grid(row=1, column=1, padx=10, sticky="ew")
        self.destino_entry.insert(0, str(self.destino))
        ttk.Button(
            config_frame,
            text="📂 Procurar",
            command=self.selecionar_destino,
            width=12
        ).grid(row=1, column=2, padx=5)
        
        config_frame.columnconfigure(1, weight=1)
        
        # Opções avançadas
        options_frame = ttk.LabelFrame(main_frame, text=" ⚙️ Opções Avançadas ", padding=10)
        options_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)
        
        options_row1 = ttk.Frame(options_frame)
        options_row1.pack(fill="x", pady=5)
        
        self.divisao_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_row1,
            text="🔄 Dividir arquivos >3.9GB (FAT32)",
            variable=self.divisao_var
        ).pack(side="left", padx=10)
        
        self.sobrescrever_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_row1,
            text="🔄 Sobrescrever arquivos existentes",
            variable=self.sobrescrever_var
        ).pack(side="left", padx=10)
        
        options_row2 = ttk.Frame(options_frame)
        options_row2.pack(fill="x", pady=5)
        
        self.verificar_integridade_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_row2,
            text="✅ Verificar integridade dos arquivos",
            variable=self.verificar_integridade_var
        ).pack(side="left", padx=10)
        
        self.criar_backup_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_row2,
            text="💾 Criar backup antes de sobrescrever",
            variable=self.criar_backup_var
        ).pack(side="left", padx=10)
        
        # Controles melhorados
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=3, column=0, columnspan=3, pady=20)
        
        self.btn_iniciar = ttk.Button(
            btn_frame,
            text="🚀 INICIAR CÓPIA",
            command=self.iniciar_copia,
            style="green.TButton",
            width=18
        )
        self.btn_iniciar.pack(side="left", padx=8)
        
        self.btn_pausar = ttk.Button(
            btn_frame,
            text="⏸️ PAUSAR",
            command=self.pausar_retomar_copia,
            width=18,
            state=tk.DISABLED
        )
        self.btn_pausar.pack(side="left", padx=8)
        
        self.btn_cancelar = ttk.Button(
            btn_frame,
            text="❌ CANCELAR",
            command=self.cancelar_copia_func,
            style="red.TButton",
            width=18,
            state=tk.DISABLED
        )
        self.btn_cancelar.pack(side="left", padx=8)
        
        ttk.Button(
            btn_frame,
            text="📄 VER LOG",
            command=self.ver_log,
            width=18
        ).pack(side="left", padx=8)
        
        # Progresso detalhado
        progress_frame = ttk.LabelFrame(main_frame, text=" 📊 Progresso da Cópia ", padding=15)
        progress_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=10)
        
        # Barra de progresso principal
        self.progresso = ttk.Progressbar(
            progress_frame,
            orient=tk.HORIZONTAL,
            length=650,
            mode='determinate'
        )
        self.progresso.pack(fill=tk.X, pady=5)
        
        # Status principal
        self.status_var = tk.StringVar()
        self.status_var.set("🟢 Pronto para iniciar a cópia.")
        status_label = ttk.Label(
            progress_frame,
            textvariable=self.status_var,
            wraplength=650,
            anchor="w",
            font=("Segoe UI", 10, "bold")
        )
        status_label.pack(fill=tk.X, pady=5)
        
        # Detalhes
        self.detalhes_var = tk.StringVar()
        self.detalhes_var.set("")
        ttk.Label(
            progress_frame,
            textvariable=self.detalhes_var,
            wraplength=650,
            anchor="w",
            foreground="#555555"
        ).pack(fill=tk.X, pady=2)
        
        # Estatísticas em tempo real
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.pack(fill="x", pady=10)
        
        self.stats_var = tk.StringVar()
        self.stats_var.set("Estatísticas: Aguardando início...")
        ttk.Label(
            stats_frame,
            textvariable=self.stats_var,
            foreground="#2c3e50",
            font=("Segoe UI", 9)
        ).pack(fill="x")
        
        # Configurar redimensionamento
        main_frame.columnconfigure(0, weight=1)
    
    def selecionar_origem(self):
        pasta = filedialog.askdirectory(
            title="Selecione a pasta com os jogos PS3",
            initialdir=str(self.origem)
        )
        if pasta:
            self.origem = Path(pasta)
            self.origem_entry.delete(0, tk.END)
            self.origem_entry.insert(0, pasta)
            self.salvar_config()
    
    def selecionar_destino(self):
        pasta = filedialog.askdirectory(
            title="Selecione a pasta de destino (FAT32)",
            initialdir=str(self.destino)
        )
        if pasta:
            self.destino = Path(pasta)
            self.destino_entry.delete(0, tk.END)
            self.destino_entry.insert(0, pasta)
            self.salvar_config()
    
    def ver_log(self):
        try:
            if Path(LOG_FILE).exists():
                os.startfile(LOG_FILE)
            else:
                messagebox.showinfo("Log", "Nenhum arquivo de log encontrado ainda.")
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível abrir o log:\n{e}")
    
    def formatar_tamanho(self, bytes_):
        """Formata tamanho em bytes para formato legível"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_ < 1024.0:
                return f"{bytes_:.2f} {unit}"
            bytes_ /= 1024.0
        return f"{bytes_:.2f} PB"
    
    def calcular_checksum(self, arquivo_path, algoritmo='md5'):
        """Calcula checksum para verificação de integridade"""
        hash_func = hashlib.md5() if algoritmo == 'md5' else hashlib.sha256()
        try:
            with open(arquivo_path, 'rb') as f:
                while chunk := f.read(TAMANHO_BUFFER):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            logging.error(f"Erro ao calcular checksum de {arquivo_path}: {e}")
            return None
    
    def verificar_espaco_disco(self, tamanho_necessario):
        """Verifica se há espaço suficiente no destino"""
        try:
            espaco_livre = shutil.disk_usage(self.destino).free
            return espaco_livre >= tamanho_necessario, espaco_livre
        except Exception as e:
            logging.error(f"Erro ao verificar espaço em disco: {e}")
            return False, 0
    
    def dividir_arquivo_otimizado(self, origem, destino_base):
        """Versão otimizada da divisão de arquivos com verificações"""
        try:
            tamanho_origem = origem.stat().st_size
            
            # Se arquivo é pequeno ou divisão está desabilitada
            if tamanho_origem <= LIMITE_FAT32 and self.divisao_var.get():
                return self.copiar_arquivo_simples(origem, destino_base)
            
            # Divisão de arquivo grande
            return self.dividir_arquivo_grande(origem, destino_base, tamanho_origem)
            
        except Exception as e:
            logging.error(f"ERRO ao processar {origem.name}: {e}")
            return [], 0
    
    def copiar_arquivo_simples(self, origem, destino):
        """Copia arquivo simples com verificação de integridade"""
        try:
            tamanho = origem.stat().st_size
            
            # Verifica se já existe e está completo
            if not self.sobrescrever_var.get() and destino.exists():
                if destino.stat().st_size == tamanho:
                    if self.verificar_integridade_var.get():
                        # Verificação rápida por tamanho e data
                        if destino.stat().st_mtime >= origem.stat().st_mtime:
                            logging.info(f"Arquivo já existe e está atualizado: {destino.name}")
                            return [destino], tamanho
                    else:
                        return [destino], tamanho
            
            # Cria backup se necessário
            if self.criar_backup_var.get() and destino.exists():
                backup_path = destino.with_suffix(f'.backup_{int(time.time())}')
                shutil.copy2(destino, backup_path)
                logging.info(f"Backup criado: {backup_path.name}")
            
            # Cópia com arquivo temporário
            temp_path = destino.with_suffix('.tmp')
            try:
                with open(origem, 'rb') as src, open(temp_path, 'wb') as dst:
                    bytes_copiados = 0
                    while chunk := src.read(TAMANHO_BUFFER):
                        if self.cancelar_copia:
                            raise InterruptedError("Operação cancelada")
                        
                        while self.pausar_copia:
                            time.sleep(0.1)
                            if self.cancelar_copia:
                                raise InterruptedError("Operação cancelada")
                        
                        dst.write(chunk)
                        bytes_copiados += len(chunk)
                
                # Verificação de integridade
                if temp_path.stat().st_size == tamanho:
                    temp_path.replace(destino)
                    logging.info(f"Arquivo copiado: {destino.name} ({self.formatar_tamanho(tamanho)})")
                    return [destino], tamanho
                else:
                    raise ValueError("Tamanho do arquivo copiado não confere")
                    
            except Exception as e:
                if temp_path.exists():
                    temp_path.unlink()
                raise e
                
        except Exception as e:
            logging.error(f"Erro ao copiar {origem.name}: {e}")
            return [], 0
    
    def dividir_arquivo_grande(self, origem, destino_base, tamanho_total):
        """Divide arquivos grandes em partes"""
        partes = []
        bytes_totais = 0
        parte_num = 0
        
        try:
            with open(origem, 'rb') as f_origem:
                while bytes_totais < tamanho_total:
                    if self.cancelar_copia:
                        raise InterruptedError("Operação cancelada")
                    
                    parte_num += 1
                    # Formato .66600, .66601, etc.
                    parte_nome = destino_base.parent / f"{destino_base.name}.666{parte_num:02d}"
                    temp_parte = parte_nome.with_suffix('.tmp')
                    
                    try:
                        with open(temp_parte, 'wb') as f_parte:
                            bytes_parte = 0
                            while bytes_parte < LIMITE_FAT32 and bytes_totais < tamanho_total:
                                while self.pausar_copia:
                                    time.sleep(0.1)
                                    if self.cancelar_copia:
                                        raise InterruptedError("Operação cancelada")
                                
                                chunk_size = min(TAMANHO_BUFFER, LIMITE_FAT32 - bytes_parte, tamanho_total - bytes_totais)
                                chunk = f_origem.read(chunk_size)
                                
                                if not chunk:
                                    break
                                
                                f_parte.write(chunk)
                                bytes_parte += len(chunk)
                                bytes_totais += len(chunk)
                        
                        # Verificação da parte
                        if temp_parte.stat().st_size > 0:
                            temp_parte.replace(parte_nome)
                            partes.append(parte_nome)
                            self.estatisticas['arquivos_divididos'] += 1
                    
                    except Exception:
                        if temp_parte.exists():
                            temp_parte.unlink()
                        raise
            
            logging.info(f"Arquivo dividido em {len(partes)} partes: {origem.name}")
            return partes, bytes_totais
            
        except Exception as e:
            logging.error(f"Erro ao dividir {origem.name}: {e}")
            # Limpeza das partes criadas
            for parte in partes:
                if parte.exists():
                    try:
                        parte.unlink()
                    except:
                        pass
            return [], 0
    
    def copiar_jogo_completo(self, pasta_jogo, destino_base, progresso_info):
        """Copia um jogo completo com todas as verificações"""
        total_copiado = 0
        arquivos_processados = 0
        
        try:
            # Cria estrutura de pastas
            os.makedirs(destino_base, exist_ok=True)
            
            # Lista todos os arquivos
            todos_arquivos = []
            for root, _, files in os.walk(pasta_jogo):
                for file in files:
                    arquivo_path = Path(root) / file
                    todos_arquivos.append(arquivo_path)
            
            total_arquivos = len(todos_arquivos)
            logging.info(f"Iniciando cópia de {pasta_jogo.name}: {total_arquivos} arquivos")
            
            # Processa cada arquivo
            for idx, arquivo in enumerate(todos_arquivos, 1):
                if self.cancelar_copia:
                    break
                
                # Calcula caminho relativo
                rel_path = arquivo.relative_to(pasta_jogo)
                destino_arquivo = destino_base / rel_path
                
                # Atualiza interface
                self.status_var.set(f"🎮 {pasta_jogo.name}: {rel_path}")
                self.detalhes_var.set(
                    f"Arquivo {idx}/{total_arquivos} • "
                    f"Tamanho: {self.formatar_tamanho(arquivo.stat().st_size)}"
                )
                self.atualizar_interface()
                
                # Cria pasta pai se necessário
                os.makedirs(destino_arquivo.parent, exist_ok=True)
                
                # Processa arquivo
                partes, bytes_copiados = self.dividir_arquivo_otimizado(arquivo, destino_arquivo)
                
                if partes:
                    total_copiado += bytes_copiados
                    arquivos_processados += len(partes)
                    progresso_info['copiado'] += bytes_copiados
                    self.progresso["value"] = progresso_info['copiado']
                    
                    # Atualiza estatísticas
                    self.estatisticas['arquivos_copiados'] += len(partes)
                    self.estatisticas['bytes_copiados'] += bytes_copiados
                
                # Atualiza estatísticas na interface
                self.atualizar_estatisticas(progresso_info)
            
            logging.info(f"Jogo concluído: {pasta_jogo.name} - {self.formatar_tamanho(total_copiado)}")
            return total_copiado, arquivos_processados
            
        except Exception as e:
            logging.error(f"Erro ao copiar jogo {pasta_jogo.name}: {e}")
            return 0, 0
    
    def atualizar_estatisticas(self, progresso_info):
        """Atualiza estatísticas em tempo real"""
        tempo_decorrido = time.time() - self.estatisticas['tempo_inicio']
        if tempo_decorrido > 0:
            velocidade = progresso_info['copiado'] / tempo_decorrido
            progresso_pct = (progresso_info['copiado'] / progresso_info['total_geral']) * 100
            tempo_restante = (progresso_info['total_geral'] - progresso_info['copiado']) / velocidade if velocidade > 0 else 0
            
            self.stats_var.set(
                f"📊 Arquivos: {self.estatisticas['arquivos_copiados']} • "
                f"Arquivos divididos: {self.estatisticas['arquivos_divididos']} • "
                f"Progresso: {progresso_pct:.1f}% • "
                f"Velocidade: {self.formatar_tamanho(velocidade)}/s • "
                f"Restante: {timedelta(seconds=int(tempo_restante))}"
            )
    
    def processo_copia_principal(self):
        """Processo principal de cópia com melhorias"""
        try:
            self.copiar_ativo = True
            self.cancelar_copia = False
            self.pausar_copia = False
            self.estatisticas['tempo_inicio'] = time.time()
            
            # Reset estatísticas
            self.estatisticas.update({
                'arquivos_copiados': 0,
                'bytes_copiados': 0,
                'arquivos_divididos': 0
            })
            
            # Análise inicial
            self.status_var.set("🔍 Analisando jogos...")
            self.detalhes_var.set("Verificando estrutura de pastas...")
            self.atualizar_interface()
            
            # Validações básicas
            if not self.origem.exists():
                raise FileNotFoundError("Pasta de origem não encontrada!")
            
            if not self.destino.exists():
                raise FileNotFoundError("Pasta de destino não encontrada!")
            
            # Lista jogos (pastas)
            jogos = [p for p in self.origem.iterdir() if p.is_dir()]
            if not jogos:
                raise ValueError("Nenhuma pasta de jogo encontrada!")
            
            logging.info(f"Encontrados {len(jogos)} jogos para cópia")
            
            # Calcula tamanho total
            tamanho_total = 0
            self.status_var.set("📏 Calculando tamanho total...")
            for jogo in jogos:
                for root, _, files in os.walk(jogo):
                    for file in files:
                        tamanho_total += (Path(root) / file).stat().st_size
                self.detalhes_var.set(f"Analisando: {jogo.name}")
                self.atualizar_interface()
            
            # Verifica espaço
            tem_espaco, espaco_livre = self.verificar_espaco_disco(tamanho_total)
            if not tem_espaco:
                raise ValueError(
                    f"Espaço insuficiente!\n"
                    f"Necessário: {self.formatar_tamanho(tamanho_total)}\n"
                    f"Disponível: {self.formatar_tamanho(espaco_livre)}"
                )
            
            # Configuração do progresso
            self.progresso["maximum"] = tamanho_total
            self.progresso["value"] = 0
            
            progresso_info = {
                'total_geral': tamanho_total,
                'copiado': 0
            }
            
            # Cópia dos jogos
            jogos_copiados = 0
            for idx, jogo in enumerate(jogos, 1):
                if self.cancelar_copia:
                    break
                
                self.status_var.set(
                    f"🎮 [{idx}/{len(jogos)}] Copiando: {jogo.name}"
                )
                self.atualizar_interface()
                
                destino_jogo = self.destino / jogo.name
                bytes_copiados, _ = self.copiar_jogo_completo(jogo, destino_jogo, progresso_info)
                
                if bytes_copiados > 0:
                    jogos_copiados += 1
            
            # Finalização
            tempo_total = time.time() - self.estatisticas['tempo_inicio']
            
            if self.cancelar_copia:
                self.status_var.set("⚠️ Cópia cancelada pelo usuário")
                messagebox.showwarning(
                    "Cancelado",
                    f"Cópia interrompida!\n\n"
                    f"Jogos processados: {jogos_copiados}/{len(jogos)}\n"
                    f"Dados copiados: {self.formatar_tamanho(progresso_info['copiado'])}"
                )
            else:
                self.status_var.set("✅ Cópia concluída com sucesso!")
                self.detalhes_var.set(
                    f"Tempo total: {timedelta(seconds=int(tempo_total))} • "
                    f"Velocidade média: {self.formatar_tamanho(progresso_info['copiado']/tempo_total)}/s"
                )
                messagebox.showinfo(
                    "Concluído! 🎉",
                    f"Cópia finalizada com sucesso!\n\n"
                    f"📁 Jogos copiados: {jogos_copiados}/{len(jogos)}\n"
                    f"📄 Arquivos processados: {self.estatisticas['arquivos_copiados']}\n"
                    f"✂️ Arquivos divididos: {self.estatisticas['arquivos_divididos']}\n"
                    f"💾 Total copiado: {self.formatar_tamanho(progresso_info['copiado'])}\n"
                    f"⏱️ Tempo: {timedelta(seconds=int(tempo_total))}\n\n"
                    f"Log salvo em: {LOG_FILE}"
                )
            
        except Exception as e:
            logging.error(f"ERRO CRÍTICO: {e}", exc_info=True)
            messagebox.showerror(
                "Erro Crítico",
                f"Ocorreu um erro durante a cópia:\n\n{str(e)}\n\n"
                f"Consulte o log para mais detalhes: {LOG_FILE}"
            )
        finally:
            # Reset do estado
            self.copiar_ativo = False
            self.cancelar_copia = False
            self.pausar_copia = False
            self.btn_iniciar["state"] = tk.NORMAL
            self.btn_pausar["state"] = tk.DISABLED
            self.btn_cancelar["state"] = tk.DISABLED
            self.atualizar_interface()
    
    def pausar_retomar_copia(self):
        """Pausa ou retoma a cópia"""
        if self.pausar_copia:
            self.pausar_copia = False
            self.btn_pausar["text"] = "⏸️ PAUSAR"
            self.status_var.set("▶️ Cópia retomada...")
        else:
            self.pausar_copia = True
            self.btn_pausar["text"] = "▶️ RETOMAR"
            self.status_var.set("⏸️ Cópia pausada...")
    
    def cancelar_copia_func(self):
        """Cancela a cópia em andamento"""
        if messagebox.askyesno("Confirmar", "Deseja realmente cancelar a cópia?"):
            self.cancelar_copia = True
            self.pausar_copia = False
            self.btn_cancelar["state"] = tk.DISABLED
            self.btn_pausar["state"] = tk.DISABLED
            self.status_var.set("🛑 Cancelando operação...")
            self.detalhes_var.set("Aguarde, finalizando operações em andamento...")
    
    def atualizar_interface(self):
        """Atualiza a interface gráfica de forma segura"""
        try:
            self.root.update_idletasks()
            self.root.update()
        except tk.TclError:
            pass  # Janela foi fechada
    
    def validar_caminhos(self):
        """Valida se os caminhos são válidos antes de iniciar"""
        self.origem = Path(self.origem_entry.get().strip())
        self.destino = Path(self.destino_entry.get().strip())
        
        if not self.origem.exists():
            raise FileNotFoundError(f"Pasta de origem não encontrada:\n{self.origem}")
        
        if not self.destino.exists():
            raise FileNotFoundError(f"Pasta de destino não encontrada:\n{self.destino}")
        
        if not self.origem.is_dir():
            raise ValueError("Origem deve ser uma pasta")
        
        if not self.destino.is_dir():
            raise ValueError("Destino deve ser uma pasta")
        
        # Verifica se não são a mesma pasta
        if self.origem.resolve() == self.destino.resolve():
            raise ValueError("Origem e destino não podem ser a mesma pasta")
    
    def iniciar_copia(self):
        """Inicia o processo de cópia com validações"""
        if self.copiar_ativo:
            return
        
        try:
            # Validações
            self.validar_caminhos()
            
            # Confirmação do usuário
            resposta = messagebox.askyesno(
                "Confirmar Cópia",
                f"Iniciar cópia de jogos PS3?\n\n"
                f"📂 Origem: {self.origem}\n"
                f"📁 Destino: {self.destino}\n\n"
                f"⚙️ Divisão de arquivos: {'✅ Ativada' if self.divisao_var.get() else '❌ Desativada'}\n"
                f"🔄 Sobrescrever: {'✅ Sim' if self.sobrescrever_var.get() else '❌ Não'}\n"
                f"✅ Verificar integridade: {'✅ Sim' if self.verificar_integridade_var.get() else '❌ Não'}\n\n"
                f"⚠️ Esta operação pode demorar dependendo do tamanho dos jogos.",
                icon='question'
            )
            
            if not resposta:
                return
            
            # Salva configurações
            self.salvar_config()
            
            # Prepara interface
            self.btn_iniciar["state"] = tk.DISABLED
            self.btn_pausar["state"] = tk.NORMAL
            self.btn_cancelar["state"] = tk.NORMAL
            
            # Inicia thread de cópia
            threading.Thread(
                target=self.processo_copia_principal,
                daemon=True,
                name="CopiaThread"
            ).start()
            
        except Exception as e:
            messagebox.showerror("Erro de Validação", str(e))
    
    def ao_fechar(self):
        """Protocolo de fechamento da aplicação"""
        if self.copiar_ativo:
            resposta = messagebox.askyesnocancel(
                "Fechar Aplicação",
                "Há uma cópia em andamento!\n\n"
                "Deseja cancelar a cópia e fechar o programa?",
                icon='warning'
            )
            
            if resposta is True:  # Sim, fechar
                self.cancelar_copia = True
                self.pausar_copia = False
                # Aguarda um pouco para a thread finalizar
                self.root.after(1000, self.root.destroy)
            elif resposta is False:  # Não, continuar
                return
            # None = Cancelar, não faz nada
        else:
            # Salva configurações antes de fechar
            self.salvar_config()
            self.root.destroy()

def main():
    """Função principal com tratamento de erros"""
    try:
        # Configuração da janela principal
        root = tk.Tk()
        root.withdraw()  # Esconde temporariamente
        
        # Cria a aplicação
        app = Split4GApp(root)
        
        # Centraliza a janela
        root.update_idletasks()
        width = root.winfo_reqwidth()
        height = root.winfo_reqheight()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Mostra a janela
        root.deiconify()
        
        # Inicia o loop principal
        root.mainloop()
        
    except Exception as e:
        logging.critical(f"ERRO CRÍTICO NA INICIALIZAÇÃO: {e}", exc_info=True)
        try:
            messagebox.showerror(
                "Erro Fatal",
                f"Erro crítico na inicialização:\n\n{str(e)}\n\n"
                f"O programa será encerrado.\n"
                f"Consulte o arquivo {LOG_FILE} para mais detalhes."
            )
        except:
            print(f"ERRO CRÍTICO: {e}")
        finally:
            import sys
            sys.exit(1)

if __name__ == "__main__":
    main()
