import os
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import time
import logging
from datetime import timedelta
import threading

# ===== CONFIGURAÇÕES GLOBAIS =====
LIMITE_FAT32 = 4 * 1024**3 - 10 * 1024**2  # 3.99GB (margem extra de segurança)
LOG_FILE = "split4g_ps3.log"
TAMANHO_BUFFER = 1024 * 1024 * 50  # 50MB (para cópia mais rápida)

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
        self.root.title("Split4G PS3 - Cópia Universal v4.0")
        self.root.geometry("650x450")
        self.root.resizable(False, False)
        
        # Configuração de estilo
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', font=('Helvetica', 10))
        self.style.configure('TLabel', font=('Helvetica', 9))
        self.style.configure('red.TButton', foreground='red', font=('Helvetica', 10, 'bold'))
        
        # Variáveis de controle
        self.origem = Path("G:/")  # Alterado para unidade G: conforme sua imagem
        self.destino = Path("D:/")  # Alterado para unidade D: conforme sua imagem
        self.copiar_ativo = False
        self.cancelar_copia = False
        
        # Interface
        self.criar_interface()
        
        # Verificar se as pastas padrão existem
        if not self.origem.exists():
            messagebox.showwarning("Aviso", f"Pasta padrão de origem não encontrada:\n{self.origem}")
        if not self.destino.exists():
            messagebox.showwarning("Aviso", f"Pasta padrão de destino não encontrada:\n{self.destino}")
    
    def criar_interface(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Título
        titulo_frame = ttk.Frame(main_frame)
        titulo_frame.grid(row=0, column=0, columnspan=3, pady=(0, 15))
        
        ttk.Label(
            titulo_frame,
            text="🛠️ SPLIT4G PS3 - CÓPIA UNIVERSAL",
            font=("Helvetica", 14, "bold"),
            foreground="#2c3e50"
        ).pack()
        
        ttk.Label(
            titulo_frame,
            text="Copia QUALQUER arquivo e divide automaticamente arquivos >4GB",
            font=("Helvetica", 9),
            foreground="#7f8c8d"
        ).pack()
        
        # Configurações
        config_frame = ttk.LabelFrame(main_frame, text=" Configurações ", padding=10)
        config_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)
        
        # Origem
        ttk.Label(config_frame, text="Pasta de Origem:").grid(row=0, column=0, sticky="w", pady=3)
        self.origem_entry = ttk.Entry(config_frame, width=50)
        self.origem_entry.grid(row=0, column=1, padx=5)
        self.origem_entry.insert(0, str(self.origem))
        ttk.Button(
            config_frame,
            text="Procurar",
            command=self.selecionar_origem,
            width=10
        ).grid(row=0, column=2, padx=5)
        
        # Destino
        ttk.Label(config_frame, text="Pasta de Destino (FAT32):").grid(row=1, column=0, sticky="w", pady=3)
        self.destino_entry = ttk.Entry(config_frame, width=50)
        self.destino_entry.grid(row=1, column=1, padx=5)
        self.destino_entry.insert(0, str(self.destino))
        ttk.Button(
            config_frame,
            text="Procurar",
            command=self.selecionar_destino,
            width=10
        ).grid(row=1, column=2, padx=5)
        
        # Opções
        options_frame = ttk.Frame(config_frame)
        options_frame.grid(row=2, column=0, columnspan=3, pady=10, sticky="w")
        
        self.divisao_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_frame,
            text="Dividir arquivos >3.99GB (FAT32)",
            variable=self.divisao_var,
            onvalue=True,
            offvalue=False
        ).pack(side="left", padx=5)
        
        self.sobrescrever_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options_frame,
            text="Sobrescrever arquivos existentes",
            variable=self.sobrescrever_var
        ).pack(side="left", padx=5)
        
        # Controles
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=0, columnspan=3, pady=15)
        
        self.btn_iniciar = ttk.Button(
            btn_frame,
            text="INICIAR CÓPIA",
            command=self.iniciar_copia,
            style="TButton",
            width=15
        )
        self.btn_iniciar.pack(side="left", padx=10)
        
        self.btn_cancelar = ttk.Button(
            btn_frame,
            text="CANCELAR",
            command=self.cancelar_copia,
            style="red.TButton",
            width=15,
            state=tk.DISABLED
        )
        self.btn_cancelar.pack(side="left", padx=10)
        
        ttk.Button(
            btn_frame,
            text="VER LOG",
            command=self.ver_log,
            width=15
        ).pack(side="left", padx=10)
        
        # Progresso
        progress_frame = ttk.LabelFrame(main_frame, text=" Progresso ", padding=10)
        progress_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=5)
        
        self.progresso = ttk.Progressbar(
            progress_frame,
            orient=tk.HORIZONTAL,
            length=600,
            mode='determinate'
        )
        self.progresso.pack(fill=tk.X, expand=True)
        
        # Status
        self.status_var = tk.StringVar()
        self.status_var.set("Pronto para iniciar a cópia.")
        ttk.Label(
            progress_frame,
            textvariable=self.status_var,
            wraplength=600,
            anchor="w"
        ).pack(fill=tk.X, pady=(10, 0))
        
        # Detalhes
        self.detalhes_var = tk.StringVar()
        self.detalhes_var.set("")
        ttk.Label(
            progress_frame,
            textvariable=self.detalhes_var,
            wraplength=600,
            anchor="w",
            foreground="#555555"
        ).pack(fill=tk.X)
    
    def selecionar_origem(self):
        pasta = filedialog.askdirectory(
            title="Selecione a pasta de origem",
            initialdir=str(self.origem)
        )
        if pasta:
            self.origem = Path(pasta)
            self.origem_entry.delete(0, tk.END)
            self.origem_entry.insert(0, pasta)
    
    def selecionar_destino(self):
        pasta = filedialog.askdirectory(
            title="Selecione a pasta de destino (FAT32)",
            initialdir=str(self.destino)
        )
        if pasta:
            self.destino = Path(pasta)
            self.destino_entry.delete(0, tk.END)
            self.destino_entry.insert(0, pasta)
    
    def ver_log(self):
        try:
            if Path(LOG_FILE).exists():
                os.startfile(LOG_FILE)
            else:
                messagebox.showinfo("Log", "Nenhum arquivo de log encontrado.")
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível abrir o log:\n{e}")
    
    def formatar_tamanho(self, bytes_):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_ < 1024.0:
                return f"{bytes_:.2f} {unit}"
            bytes_ /= 1024.0
        return f"{bytes_:.2f} TB"
    
    def verificar_espaco(self, necessario):
        try:
            espaco_livre = shutil.disk_usage(self.destino).free
            return espaco_livre >= necessario
        except Exception as e:
            logging.error(f"Erro ao verificar espaço: {e}")
            return False
    
    def dividir_arquivo(self, origem, destino_base):
        """Divide arquivos >3.99GB em partes .66600, .66601, ..."""
        try:
            tamanho = origem.stat().st_size
            if tamanho <= LIMITE_FAT32 or not self.divisao_var.get():
                if not self.sobrescrever_var.get() and destino_base.exists():
                    if destino_base.stat().st_size == tamanho:
                        logging.info(f"Arquivo já existe (pulando): {destino_base.name}")
                        return [destino_base], tamanho
                
                shutil.copy2(origem, destino_base)
                logging.info(f"Arquivo copiado: {destino_base.name}")
                return [destino_base], tamanho
            
            partes = []
            bytes_totais = 0
            parte_num = 0
            
            with open(origem, 'rb') as f_origem:
                while True:
                    parte_num += 1
                    parte_nome = destino_base.parent / f"{destino_base.name}.666{parte_num:02}"
                    partes.append(parte_nome)
                    
                    with open(parte_nome, 'wb') as f_parte:
                        copiado = 0
                        while copiado < LIMITE_FAT32:
                            if self.cancelar_copia:
                                return [], 0
                            
                            dados = f_origem.read(TAMANHO_BUFFER)
                            if not dados:
                                logging.info(f"Arquivo dividido em {len(partes)} partes: {origem.name}")
                                return partes, bytes_totais
                            
                            f_parte.write(dados)
                            copiado += len(dados)
                            bytes_totais += len(dados)
                            
                            # Atualiza interface a cada 50MB copiados
                            if copiado % (50 * 1024 * 1024) == 0:
                                self.atualizar_interface()
            
        except Exception as e:
            logging.error(f"ERRO ao dividir {origem.name}: {e}")
            # Remove partes incompletas em caso de erro
            for parte in partes:
                if parte.exists():
                    try:
                        parte.unlink()
                    except:
                        pass
            return [], 0
    
    def copiar_tudo(self):
        """Copia TODOS os arquivos recursivamente, dividindo os grandes"""
        try:
            self.copiar_ativo = True
            self.cancelar_copia = False
            inicio_geral = time.time()
            total_geral_bytes = 0
            total_arquivos = 0
            
            # Lista todos os arquivos
            todos_arquivos = []
            for raiz, _, arquivos in os.walk(self.origem):
                for arquivo in arquivos:
                    caminho_completo = Path(raiz) / arquivo
                    todos_arquivos.append(caminho_completo)
            
            if not todos_arquivos:
                messagebox.showinfo("Info", "Nenhum arquivo encontrado na pasta de origem!")
                return
            
            # Calcula tamanho total
            for arquivo in todos_arquivos:
                total_geral_bytes += arquivo.stat().st_size
            total_arquivos = len(todos_arquivos)
            
            # Fase 1: Preparação
            self.status_var.set(f"🔍 Preparando para copiar {total_arquivos} arquivos...")
            self.detalhes_var.set(f"Tamanho total: {self.formatar_tamanho(total_geral_bytes)}")
            self.progresso["value"] = 0
            self.progresso["maximum"] = total_geral_bytes
            self.atualizar_interface()
            
            # Verifica espaço em disco
            if not self.verificar_espaco(total_geral_bytes):
                espaco_livre = shutil.disk_usage(self.destino).free
                messagebox.showerror(
                    "Erro de Espaço",
                    f"Espaço insuficiente no destino!\n\n"
                    f"Necessário: {self.formatar_tamanho(total_geral_bytes)}\n"
                    f"Disponível: {self.formatar_tamanho(espaco_livre)}\n\n"
                    f"Libere espaço ou selecione outro destino."
                )
                return
            
            # Fase 2: Cópia
            total_copiado_bytes = 0
            arquivos_copiados = 0
            
            for idx, arquivo in enumerate(todos_arquivos, 1):
                if self.cancelar_copia:
                    break
                
                # Caminho relativo para manter estrutura de pastas
                rel_path = arquivo.relative_to(self.origem)
                destino_arquivo = self.destino / rel_path
                
                # Cria pasta de destino se necessário
                os.makedirs(destino_arquivo.parent, exist_ok=True)
                
                # Atualiza status
                self.status_var.set(f"📁 Copiando: {rel_path}")
                self.detalhes_var.set(
                    f"Arquivo {idx}/{total_arquivos} | "
                    f"Tamanho: {self.formatar_tamanho(arquivo.stat().st_size)}"
                )
                self.atualizar_interface()
                
                # Verifica se já existe e está completo
                if not self.sobrescrever_var.get() and destino_arquivo.exists():
                    if destino_arquivo.stat().st_size == arquivo.stat().st_size:
                        total_copiado_bytes += arquivo.stat().st_size
                        arquivos_copiados += 1
                        self.progresso["value"] = total_copiado_bytes
                        continue
                    else:
                        try:
                            destino_arquivo.unlink()
                        except Exception as e:
                            logging.error(f"Erro ao remover arquivo incompleto: {destino_arquivo} - {e}")
                
                # Cópia real (com divisão se necessário)
                partes, tamanho_copiado = self.dividir_arquivo(arquivo, destino_arquivo)
                if partes:
                    total_copiado_bytes += tamanho_copiado
                    arquivos_copiados += len(partes)
                    self.progresso["value"] = total_copiado_bytes
                
                # Atualiza status
                tempo_passado = time.time() - inicio_geral
                progresso = total_copiado_bytes / total_geral_bytes
                tempo_restante = (tempo_passado / progresso) - tempo_passado if progresso > 0 else 0
                
                velocidade = total_copiado_bytes / tempo_passado if tempo_passado > 0 else 0
                
                self.detalhes_var.set(
                    f"Progresso: {self.formatar_tamanho(total_copiado_bytes)}/"
                    f"{self.formatar_tamanho(total_geral_bytes)} | "
                    f"Velocidade: {self.formatar_tamanho(velocidade)}/s | "
                    f"Tempo decorrido: {timedelta(seconds=int(tempo_passado))} | "
                    f"Restante: ~{timedelta(seconds=int(tempo_restante))}"
                )
                self.atualizar_interface()
            
            # Conclusão
            tempo_total = time.time() - inicio_geral
            if self.cancelar_copia:
                self.status_var.set("⚠️ Cópia interrompida pelo usuário!")
                messagebox.showwarning(
                    "Interrompido",
                    "A cópia foi cancelada pelo usuário!\n\n"
                    f"Progresso: {self.formatar_tamanho(total_copiado_bytes)}/"
                    f"{self.formatar_tamanho(total_geral_bytes)} copiados."
                )
            else:
                self.status_var.set("✅ Cópia concluída com sucesso!")
                self.detalhes_var.set(
                    f"Total copiado: {self.formatar_tamanho(total_copiado_bytes)} | "
                    f"Tempo total: {timedelta(seconds=int(tempo_total))} | "
                    f"Velocidade média: {self.formatar_tamanho(total_copiado_bytes/tempo_total)}/s"
                )
                messagebox.showinfo(
                    "Concluído",
                    f"Cópia finalizada com sucesso!\n\n"
                    f"Arquivos copiados: {arquivos_copiados}\n"
                    f"Tempo total: {timedelta(seconds=int(tempo_total))}\n\n"
                    f"Log salvo em: {LOG_FILE}"
                )
            
        except Exception as e:
            logging.error(f"ERRO GLOBAL: {str(e)}", exc_info=True)
            messagebox.showerror(
                "Erro Fatal",
                f"Ocorreu um erro durante a cópia:\n\n{str(e)}\n\n"
                f"Consulte o arquivo de log para detalhes: {LOG_FILE}"
            )
        finally:
            self.copiar_ativo = False
            self.cancelar_copia = False
            self.btn_iniciar["state"] = tk.NORMAL
            self.btn_cancelar["state"] = tk.DISABLED
            self.atualizar_interface()
    
    def cancelar_copia(self):
        self.cancelar_copia = True
        self.btn_cancelar["state"] = tk.DISABLED
        self.status_var.set("⏳ Finalizando operação...")
        self.detalhes_var.set("Aguarde, salvando dados parciais...")
        self.atualizar_interface()
    
    def atualizar_interface(self):
        """Atualiza a interface gráfica"""
        try:
            self.root.update_idletasks()
            self.root.update()
        except:
            pass
    
    def iniciar_copia(self):
        """Inicia o processo de cópia em uma thread separada"""
        if self.copiar_ativo:
            return
        
        if not self.origem.exists():
            messagebox.showerror("Erro", "Pasta de origem não encontrada!")
            return
        
        if not self.destino.exists():
            messagebox.showerror("Erro", "Pasta de destino não encontrada!")
            return
        
        # Confirmação final
        confirmar = messagebox.askyesno(
            "Confirmar",
            "Deseja iniciar a cópia dos arquivos?\n\n"
            f"Origem: {self.origem}\n"
            f"Destino: {self.destino}\n\n"
            f"Esta operação pode demorar dependendo da quantidade de dados.",
            icon='question'
        )
        
        if not confirmar:
            return
        
        self.btn_iniciar["state"] = tk.DISABLED
        self.btn_cancelar["state"] = tk.NORMAL
        
        # Inicia em uma thread separada para não travar a interface
        threading.Thread(
            target=self.copiar_tudo,
            daemon=True
        ).start()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = Split4GApp(root)
        
        # Centraliza a janela
        window_width = root.winfo_reqwidth()
        window_height = root.winfo_reqheight()
        position_right = int(root.winfo_screenwidth()/2 - window_width/2)
        position_down = int(root.winfo_screenheight()/2 - window_height/2)
        root.geometry(f"+{position_right}+{position_down}")
        
        root.mainloop()
    except Exception as e:
        logging.critical(f"ERRO CRÍTICO: {str(e)}", exc_info=True)
        messagebox.showerror(
            "Erro Inesperado",
            f"Ocorreu um erro crítico:\n\n{str(e)}\n\n"
            "O programa será encerrado."
        )