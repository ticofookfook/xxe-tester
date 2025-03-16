#!/usr/bin/env python3
"""
XXE Tester - Ferramenta para testes automatizados de payloads XXE

Esta ferramenta recebe uma URL alvo e uma pasta contendo payloads XXE,
envia cada payload para o alvo e analisa as respostas para identificar
possíveis vulnerabilidades XXE.
"""

import argparse
import os
import re
import sys
import time
from urllib.parse import urlparse
import concurrent.futures
import random
from typing import List, Dict, Tuple, Optional, Any

try:
    import requests
    from requests.exceptions import RequestException
    from rich.console import Console
    from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
except ImportError:
    print("Dependências não encontradas. Instalando...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "rich"])
    
    import requests
    from requests.exceptions import RequestException
    from rich.console import Console
    from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel

# Inicialização do console para saída formatada
console = Console()

class XXETester:
    def __init__(
            self, 
            target_url: str, 
            payloads_dir: str, 
            method: str = "POST",
            threads: int = 1,
            timeout: int = 10,
            delay: float = 0.0,
            user_agent: str = None,
            cookies: Dict[str, str] = None,
            headers: Dict[str, str] = None,
            data_param: str = None,
            detect_success: str = None,
            verbose: bool = False,
            output_file: str = None
        ):
        """Inicializa o testador de XXE."""
        self.target_url = target_url
        self.payloads_dir = payloads_dir
        self.method = method.upper()
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.output_file = output_file
        self.detect_success = detect_success
        self.data_param = data_param
        
        # Configuração dos cabeçalhos
        self.headers = {
            'User-Agent': user_agent or 'XXE-Tester/1.0',
        }
        if headers:
            self.headers.update(headers)
            
        self.cookies = cookies or {}
        
        # Resultados
        self.results = []
        self.successful_payloads = []
        self.errors = []
        
        # Estatísticas
        self.stats = {
            'total_payloads': 0,
            'successful_payloads': 0,
            'error_payloads': 0,
            'start_time': None,
            'end_time': None
        }

    def detect_encoding(self, file_path: str) -> Optional[str]:
        """Detecta a codificação do arquivo XML baseado nos primeiros bytes."""
        try:
            with open(file_path, 'rb') as f:
                first_bytes = f.read(4)
                
                # Detecção de BOM
                if first_bytes.startswith(b'\xff\xfe\x00\x00'):
                    return 'UTF-32LE'
                elif first_bytes.startswith(b'\x00\x00\xfe\xff'):
                    return 'UTF-32BE'
                elif first_bytes.startswith(b'\xff\xfe'):
                    return 'UTF-16LE'
                elif first_bytes.startswith(b'\xfe\xff'):
                    return 'UTF-16BE'
                elif first_bytes.startswith(b'\xef\xbb\xbf'):
                    return 'UTF-8-SIG'
                
                # Se não tem BOM, tentar encontrar a declaração XML
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as text_f:
                    first_line = text_f.readline()
                    encoding_match = re.search(r'encoding=["\']([^"\']+)["\']', first_line)
                    if encoding_match:
                        return encoding_match.group(1)
                
                return 'UTF-8'  # Default
        except Exception as e:
            console.print(f"[yellow]Aviso: Não foi possível detectar a codificação de {file_path}: {str(e)}[/yellow]")
            return None

    def get_payload_files(self) -> List[str]:
        """Retorna uma lista de todos os arquivos XML na pasta de payloads."""
        payload_files = []
        
        if not os.path.exists(self.payloads_dir):
            console.print(f"[red]Erro: A pasta {self.payloads_dir} não existe![/red]")
            sys.exit(1)
            
        for file in os.listdir(self.payloads_dir):
            if file.endswith('.xml'):
                payload_files.append(os.path.join(self.payloads_dir, file))
                
        if not payload_files:
            console.print(f"[yellow]Aviso: Nenhum arquivo XML encontrado em {self.payloads_dir}[/yellow]")
            sys.exit(1)
            
        return payload_files

    def prepare_request_data(self, payload_file: str) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """Prepara os dados e cabeçalhos para o request baseado no payload."""
        # Detecta a codificação do arquivo
        encoding = self.detect_encoding(payload_file)
        
        # Prepara os cabeçalhos específicos para este payload
        headers = self.headers.copy()
        if encoding:
            headers['Content-Type'] = f'application/xml; charset={encoding}'
        else:
            headers['Content-Type'] = 'application/xml'
            
        # Lê o arquivo como binário para preservar a codificação
        with open(payload_file, 'rb') as f:
            payload_data = f.read()
        
        # Se tiver um parâmetro específico, envia como parte de um formulário
        if self.data_param:
            data = {self.data_param: payload_data}
        else:
            data = payload_data
            
        return data, headers

    def test_payload(self, payload_file: str) -> Dict[str, Any]:
        """Testa um único payload contra o alvo e retorna os resultados."""
        result = {
            'payload_file': payload_file,
            'payload_name': os.path.basename(payload_file),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'success': False,
            'response_code': None,
            'response_size': 0,
            'response_time': 0,
            'error': None,
            'encoding': self.detect_encoding(payload_file)
        }
        
        try:
            # Prepara os dados e cabeçalhos
            data, headers = self.prepare_request_data(payload_file)
            
            # Adiciona um delay se especificado
            if self.delay > 0:
                time.sleep(self.delay)
                
            # Faz o request
            start_time = time.time()
            
            if self.method == 'POST':
                response = requests.post(
                    self.target_url,
                    data=data,
                    headers=headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=False  # Desabilita verificação SSL para testes
                )
            elif self.method == 'PUT':
                response = requests.put(
                    self.target_url,
                    data=data,
                    headers=headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=False
                )
            else:  # GET ou outro método
                response = requests.request(
                    self.method,
                    self.target_url,
                    data=data,
                    headers=headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=False
                )
                
            response_time = time.time() - start_time
            
            # Registra os resultados
            result['response_code'] = response.status_code
            result['response_size'] = len(response.content)
            result['response_time'] = response_time
            
            # Verifica se foi bem-sucedido baseado no padrão de detecção
            if self.detect_success:
                result['success'] = self.detect_success in response.text
            else:
                # Se não houver padrão, considere sucesso baseado em heurísticas
                # Por exemplo, resposta 200, conteúdo incomum, etc.
                result['success'] = (
                    response.status_code == 200 and 
                    len(response.content) > 0 and
                    "error" not in response.text.lower()
                )
                
            # Se for verboso, adiciona o conteúdo da resposta
            if self.verbose:
                result['response_content'] = response.text[:500]  # Limita o tamanho para não sobrecarregar
                
        except RequestException as e:
            result['error'] = str(e)
            result['success'] = False
            
        except Exception as e:
            result['error'] = f"Erro inesperado: {str(e)}"
            result['success'] = False
            
        return result

    def run_tests(self):
        """Executa os testes em todos os payloads disponíveis."""
        payload_files = self.get_payload_files()
        self.stats['total_payloads'] = len(payload_files)
        self.stats['start_time'] = time.time()
        
        console.print(f"[bold green]Iniciando testes com {len(payload_files)} payloads contra {self.target_url}[/bold green]")
        
        # Mostra um resumo dos arquivos de payload encontrados
        table = Table(title="Payloads Encontrados")
        table.add_column("Arquivo", style="cyan")
        table.add_column("Tamanho", style="magenta")
        table.add_column("Codificação", style="green")
        
        # Apenas mostra até 10 payloads para não sobrecarregar a tela
        for payload_file in payload_files[:10]:
            file_size = os.path.getsize(payload_file)
            encoding = self.detect_encoding(payload_file)
            table.add_row(os.path.basename(payload_file), f"{file_size} bytes", encoding or "Desconhecida")
            
        if len(payload_files) > 10:
            table.add_row("...", "...", "...")
            
        console.print(table)
        
        # Usa Progress para mostrar o progresso dos testes
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[bold]{task.completed}/{task.total}"),
            TimeElapsedColumn()
        ) as progress:
            task = progress.add_task("[cyan]Testando payloads...", total=len(payload_files))
            
            # Executa os testes em paralelo se threads > 1
            if self.threads > 1:
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    future_to_payload = {executor.submit(self.test_payload, payload_file): payload_file for payload_file in payload_files}
                    
                    for future in concurrent.futures.as_completed(future_to_payload):
                        result = future.result()
                        self.results.append(result)
                        
                        if result['success']:
                            self.successful_payloads.append(result)
                            self.stats['successful_payloads'] += 1
                        elif result['error']:
                            self.errors.append(result)
                            self.stats['error_payloads'] += 1
                            
                        progress.update(task, advance=1)
            else:
                # Executa em modo single-thread
                for payload_file in payload_files:
                    result = self.test_payload(payload_file)
                    self.results.append(result)
                    
                    if result['success']:
                        self.successful_payloads.append(result)
                        self.stats['successful_payloads'] += 1
                    elif result['error']:
                        self.errors.append(result)
                        self.stats['error_payloads'] += 1
                        
                    progress.update(task, advance=1)
                    
        self.stats['end_time'] = time.time()
        self._print_results()
        
        if self.output_file:
            self._save_results()

    def _print_results(self):
        """Imprime os resultados dos testes."""
        console.print("\n[bold green]Testes concluídos![/bold green]")
        
        # Estatísticas
        execution_time = self.stats['end_time'] - self.stats['start_time']
        
        stats_table = Table(title="Estatísticas dos Testes")
        stats_table.add_column("Métrica", style="cyan")
        stats_table.add_column("Valor", style="green")
        
        stats_table.add_row("Total de Payloads", str(self.stats['total_payloads']))
        stats_table.add_row("Payloads com Sucesso", str(self.stats['successful_payloads']))
        stats_table.add_row("Payloads com Erro", str(self.stats['error_payloads']))
        stats_table.add_row("Tempo Total de Execução", f"{execution_time:.2f} segundos")
        stats_table.add_row("Média por Payload", f"{execution_time / max(1, self.stats['total_payloads']):.2f} segundos")
        
        console.print(stats_table)
        
        # Payloads com sucesso
        if self.successful_payloads:
            console.print("\n[bold green]Payloads com Sucesso:[/bold green]")
            success_table = Table(show_header=True)
            success_table.add_column("Arquivo", style="cyan")
            success_table.add_column("Codificação", style="green")
            success_table.add_column("Tempo de Resposta", style="magenta")
            success_table.add_column("Tamanho da Resposta", style="blue")
            
            for result in self.successful_payloads:
                success_table.add_row(
                    result['payload_name'],
                    result['encoding'] or "Desconhecida",
                    f"{result['response_time']:.3f}s",
                    f"{result['response_size']} bytes"
                )
                
            console.print(success_table)
            
            # Se for verboso, mostra detalhes das respostas
            if self.verbose:
                for i, result in enumerate(self.successful_payloads):
                    console.print(f"\n[bold cyan]Detalhes do Payload #{i+1}: {result['payload_name']}[/bold cyan]")
                    if 'response_content' in result:
                        console.print(Panel(
                            Text(result['response_content'], style="green"), 
                            title="Conteúdo da Resposta (trecho)"
                        ))
        
        # Erros
        if self.errors:
            console.print("\n[bold red]Erros encontrados:[/bold red]")
            error_table = Table(show_header=True)
            error_table.add_column("Arquivo", style="cyan")
            error_table.add_column("Erro", style="red")
            
            for result in self.errors:
                error_table.add_row(
                    result['payload_name'],
                    result['error'] or "Erro desconhecido"
                )
                
            console.print(error_table)
            
        # Recomendações
        console.print("\n[bold yellow]Recomendações:[/bold yellow]")
        if self.successful_payloads:
            console.print("[green]✓ Foram encontrados payloads que podem ter sido bem-sucedidos![/green]")
            console.print("[yellow]- Examine manualmente as respostas para confirmar a vulnerabilidade XXE[/yellow]")
            console.print("[yellow]- Teste os payloads bem-sucedidos com parâmetros diferentes[/yellow]")
        else:
            console.print("[yellow]- Tente diferentes métodos HTTP (GET, POST, PUT)[/yellow]")
            console.print("[yellow]- Verifique se o alvo aceita conteúdo XML[/yellow]")
            console.print("[yellow]- Teste com codificações diferentes (UTF-16LE é frequentemente eficaz)[/yellow]")
            console.print("[yellow]- Teste com técnicas de ofuscação adicionais[/yellow]")

    def _save_results(self):
        """Salva os resultados em um arquivo."""
        try:
            import json
            
            output_data = {
                'target': self.target_url,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'stats': self.stats,
                'successful_payloads': self.successful_payloads,
                'errors': self.errors,
                'all_results': self.results
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
                
            console.print(f"[green]Resultados salvos em: {self.output_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]Erro ao salvar resultados: {str(e)}[/red]")


def validate_url(url: str) -> str:
    """Valida se a URL está em um formato correto."""
    try:
        result = urlparse(url)
        if all([result.scheme, result.netloc]):
            return url
        raise ValueError()
    except ValueError:
        raise argparse.ArgumentTypeError(f"URL inválida: {url}")


def main():
    parser = argparse.ArgumentParser(
        description="XXE Tester - Ferramenta para testes automatizados de payloads XXE",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "target_url",
        type=validate_url,
        help="URL do alvo (ex: https://exemplo.com/endpoint)"
    )
    
    parser.add_argument(
        "payloads_dir",
        help="Diretório contendo os arquivos XML de payload"
    )
    
    parser.add_argument(
        "-m", "--method",
        choices=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
        default="POST",
        help="Método HTTP a ser usado"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=1,
        help="Número de threads para execução em paralelo"
    )
    
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.0,
        help="Delay em segundos entre requests"
    )
    
    parser.add_argument(
        "-to", "--timeout",
        type=int,
        default=10,
        help="Timeout em segundos para cada request"
    )
    
    parser.add_argument(
        "-ua", "--user-agent",
        help="User-Agent personalizado"
    )
    
    parser.add_argument(
        "-c", "--cookie",
        action="append",
        help="Cookies no formato 'nome=valor' (pode ser usado múltiplas vezes)"
    )
    
    parser.add_argument(
        "-H", "--header",
        action="append",
        help="Cabeçalhos adicionais no formato 'Nome: Valor' (pode ser usado múltiplas vezes)"
    )
    
    parser.add_argument(
        "-p", "--param",
        help="Nome do parâmetro para enviar o payload (se não especificado, envia como corpo raw)"
    )
    
    parser.add_argument(
        "-ds", "--detect-success",
        help="String que indica sucesso na resposta (ex: 'root:' para leitura de /etc/passwd)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Modo verboso - mostra mais detalhes sobre as respostas"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Arquivo para salvar os resultados em formato JSON"
    )
    
    args = parser.parse_args()
    
    # Configura requests para ignorar avisos SSL
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Processa cookies
    cookies = {}
    if args.cookie:
        for cookie in args.cookie:
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name] = value
    
    # Processa cabeçalhos
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                name, value = header.split(':', 1)
                headers[name.strip()] = value.strip()
    
    # Mostra a logo
    logo = """
██╗  ██╗██╗  ██╗███████╗    ████████╗███████╗███████╗████████╗███████╗██████╗ 
╚██╗██╔╝╚██╗██╔╝██╔════╝    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ╚███╔╝  ╚███╔╝ █████╗         ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
 ██╔██╗  ██╔██╗ ██╔══╝         ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
██╔╝ ██╗██╔╝ ██╗███████╗       ██║   ███████╗███████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                          v1.0                                                                
    """
    console.print(f"[bold cyan]{logo}[/bold cyan]")
    console.print("[bold yellow]XXE Tester - Ferramenta para Testes Automatizados de Payloads XXE[/bold yellow]\n")
    
    # Cria e executa o testador
    tester = XXETester(
        target_url=args.target_url,
        payloads_dir=args.payloads_dir,
        method=args.method,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
        cookies=cookies,
        headers=headers,
        data_param=args.param,
        detect_success=args.detect_success,
        verbose=args.verbose,
        output_file=args.output
    )
    
    tester.run_tests()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Teste interrompido pelo usuário.[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Erro: {str(e)}[/bold red]")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)
