import sys
import logging
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

from utils import run_nmap_scan, check_nmap, is_valid_target, analyze_scan_with_ai
from db import init_db, save_scan, get_history

# Setup simple console logging instead of file logging for CLI
logging.basicConfig(level=logging.ERROR, format="%(message)s")

console = Console()

def display_header():
    console.clear()
    header = Text("🚀 AI Assistant - Network Scanner", style="bold cyan", justify="center")
    console.print(Panel(header, border_style="cyan"))
    console.print()

def menu():
    while True:
        display_header()
        console.print("[1] 🌐 Scan a Target", style="bold green")
        console.print("[2] 📜 View Scan History", style="bold yellow")
        console.print("[3] 🛠️  Check Nmap Status", style="bold blue")
        console.print("[4] ❌ Exit", style="bold red")
        console.print()
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            handle_scan()
        elif choice == "2":
            handle_history()
        elif choice == "3":
            handle_check_nmap()
        elif choice == "4":
            console.print("Goodbye! 👋", style="bold magenta")
            sys.exit(0)

def handle_scan():
    console.print("\n[bold cyan]--- New Scan ---[/bold cyan]")
    target = Prompt.ask("Enter target IP or domain (e.g., 192.168.1.1)")
    
    if not is_valid_target(target):
        console.print("[bold red]Invalid target. Please provide a valid IP address or domain name.[/bold red]")
        Prompt.ask("Press Enter to continue")
        return

    scan_type = Prompt.ask("Select scan type", choices=["fast", "advanced"], default="fast")

    with console.status(f"[bold green]Scanning {target} ({scan_type} mode)... This may take a moment.[/bold green]"):
        success, result = run_nmap_scan(target, scan_type=scan_type)

    if success:
        console.print("[bold green]Scan completed successfully![/bold green]")
        console.print(Panel(result, title=f"Raw Results for {target}", border_style="green"))
        
        with console.status("[bold blue]🤖 AI is analyzing the scan results...[/bold blue]"):
            ai_analysis = analyze_scan_with_ai(result)
            
        console.print(Panel(ai_analysis, title="🧠 AI Cybersecurity Analysis", border_style="magenta"))
        
        # Save both to the database
        save_scan(target, f"--- NMAP RAW ---\n{result}\n\n--- AI ANALYSIS ---\n{ai_analysis}")
    else:
        console.print(f"[bold red]Scan failed:[/bold red]\n{result}")

    Prompt.ask("\nPress Enter to return to menu")

def handle_history():
    console.print("\n[bold cyan]--- Scan History ---[/bold cyan]")
    history = get_history()
    
    if not history:
        console.print("No scan history found.", style="italic yellow")
        Prompt.ask("\nPress Enter to return to menu")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=6)
    table.add_column("Target", min_width=15)
    table.add_column("Timestamp", min_width=20)
    
    for row in history:
        # id, target, timestamp, result
        table.add_row(str(row[0]), row[1], row[2])
        
    console.print(table)
    
    if Confirm.ask("Do you want to view details of a specific scan?"):
        scan_id = Prompt.ask("Enter the Scan ID")
        
        # Find the scan in the history
        selected_scan = next((s for s in history if str(s[0]) == scan_id), None)
        if selected_scan:
            console.print(Panel(selected_scan[3], title=f"Results for {selected_scan[1]} at {selected_scan[2]}", border_style="green"))
        else:
            console.print("[bold red]Invalid Scan ID.[/bold red]")
            
    Prompt.ask("\nPress Enter to return to menu")

def handle_check_nmap():
    console.print("\n[bold cyan]--- Nmap Status ---[/bold cyan]")
    with console.status("Checking Nmap installation..."):
        is_installed = check_nmap()
        
    if is_installed:
        console.print("[bold green]✅ Nmap is installed and available in the system PATH.[/bold green]")
    else:
        console.print("[bold red]❌ Nmap is NOT installed or not found in the system PATH.[/bold red]")
        console.print("Please install Nmap to use the scanning features.")
        
    Prompt.ask("\nPress Enter to return to menu")

if __name__ == "__main__":
    init_db()
    try:
        menu()
    except KeyboardInterrupt:
        console.print("\nExiting... Goodbye! 👋", style="bold magenta")
        sys.exit(0)
