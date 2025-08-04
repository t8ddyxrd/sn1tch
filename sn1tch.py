import re
import argparse
import time
import random
import threading
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from pyfiglet import Figlet
from geo import get_geo
from utils import (
    save_results,
    block_ip,
    get_stats,
    is_blocked,
    load_config,
    send_discord_alert 
)

console = Console()

FAKE_USERS = [
    "root", "admin", "test", "user", "ubuntu", "oracle", "postgres", "mysql", "git", "dev"
]

def generate_random_ip():
    while True:
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        if not ip.startswith(("10.", "192.168.", "172.", "127.")):
            return ip

def print_banner(use_geo):
    figlet = Figlet(font='ogre')
    banner = figlet.renderText("sn1tch")
    console.print(banner, style="red")
    console.print("[white]v1.0 by t8ddy[/white]")
    if use_geo:
        console.print("[bold green]GEOIP LOOKUP ENABLED[/bold green]\n")
    else:
        console.print("[yellow]GeoIP Lookup: Disabled[/yellow]\n")

def generate_fake_entries(file_path, count):
    with open(file_path, "a") as f:
        for _ in range(count):
            ip = generate_random_ip()
            user = random.choice(FAKE_USERS)
            hour = str(random.randint(0, 23)).zfill(2)
            minute = str(random.randint(0, 59)).zfill(2)
            second = str(random.randint(0, 59)).zfill(2)
            port = random.randint(1024, 65535)
            pid = random.randint(1000, 99999)
            log_line = f"Aug 5 {hour}:{minute}:{second} server sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2\n"
            f.write(log_line)
    console.print(f"[bold cyan]Injected {count} randomized fake failed logins into {file_path}[/bold cyan]")

def simulate_attack_loop(file_path, interval=3):
    def simulate():
        while True:
            generate_fake_entries(file_path, 1)
            time.sleep(interval)

    thread = threading.Thread(target=simulate, daemon=True)
    thread.start()

def parse_log(file_path):
    FAILED_LOGIN_PATTERN = r"Failed password for (invalid user )?(\w+) from ([\d\.]+)"
    failed_attempts = defaultdict(int)
    try:
        with open(file_path, "r") as f:
            for line in f:
                match = re.search(FAILED_LOGIN_PATTERN, line)
                if match:
                    ip = match.group(3)
                    failed_attempts[ip] += 1
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Log file '{file_path}' not found.")
        exit(1)
    return failed_attempts

def print_alerts(failed_attempts, threshold, use_geo=False, do_save=False, do_block=False, show_stats=False, alert_discord=False):
    table = Table(
        title=f"Suspicious IPs: ({threshold}+ Failed Logins)",
        title_style="red",
        header_style="red",
        style="red",
        border_style="red"
    )
    table.add_column("IP Address", style="red", no_wrap=True)
    table.add_column("Failed Attempts", style="red", justify="center")
    table.add_column("Location", style="red", justify="left")
    entries = []
    printed = False
    for ip, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True):
        if count >= threshold:
            location = get_geo(ip) if use_geo else "GeoIP Disabled"
            if do_block:
                block_ip(ip)
            if alert_discord:
                send_discord_alert(ip, count, location)
            entries.append({"ip": ip, "attempts": count, "location": location})
            table.add_row(ip, str(count), location or "Unknown")
            printed = True
    if printed:
        console.print(table)
        if show_stats:
            stats = get_stats(failed_attempts)
            console.print(f"\n[bold white]Stats:[/bold white]")
            console.print(f"Total Failed Attempts: {stats['total_failed_attempts']}")
            console.print(f"Unique IPs: {stats['unique_ips']}")
        if do_save:
            save_results(entries)
    else:
        console.print(f"[white]No IPs with {threshold}+ failed login attempts found.[/white]")

def track_live_log(file_path, threshold, use_geo=False, do_save=False, do_block=False, alert_discord=False):
    seen = defaultdict(int)
    printed = set()
    console.print("[bold green]Live tracking started... Press Ctrl+C to stop[/bold green]")
    try:
        with open(file_path, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                match = re.search(r"Failed password for (invalid user )?(\w+) from ([\d\.]+)", line)
                if match:
                    ip = match.group(3)
                    seen[ip] += 1
                    if seen[ip] >= threshold and ip not in printed:
                        location = get_geo(ip) if use_geo else "GeoIP Disabled"
                        if do_block:
                            block_ip(ip)
                        if do_save:
                            save_results([{ "ip": ip, "attempts": seen[ip], "location": location }])
                        if alert_discord:
                            send_discord_alert(ip, seen[ip], location)
                        console.print(f"[bold red]LIVE DETECTED →[/bold red] IP: [yellow]{ip}[/yellow] | Attempts: {seen[ip]} | Location: {location}")
                        printed.add(ip)
    except KeyboardInterrupt:
        console.print("\n[bold cyan]Live tracking stopped.[/bold cyan]")
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Log file '{file_path}' not found.")

def main():
    parser = argparse.ArgumentParser(description="sN1TCH – SSH brute-force snitch tool")
    parser.add_argument("--file", default="sample_auth.log", help="Path to the log file")
    parser.add_argument("--threshold", type=int, default=5, help="Minimum failed attempts to trigger alert")
    parser.add_argument("--geo", action="store_true", help="Enable GeoIP lookup")
    parser.add_argument("--save", action="store_true", help="Save output to data/output.json")
    parser.add_argument("--block", action="store_true", help="Auto-block IPs via UFW")
    parser.add_argument("--stats", action="store_true", help="Show total login stats")
    parser.add_argument("--alert", action="store_true", help="Send alerts to Discord")
    parser.add_argument("--live", action="store_true", help="Enable real-time log tracking")
    parser.add_argument("--test", type=int, help="Inject N fake log entries for testing")
    parser.add_argument("--simulate", action="store_true", help="Continuously inject fake logs while tracking")
    parser.add_argument("--version", action="version", version="sN1TCH v1.0 by t8ddy")
    args = parser.parse_args()
    print_banner(use_geo=args.geo)
    if args.simulate:
        simulate_attack_loop(args.file, interval=2)
    if args.test:
        generate_fake_entries(args.file, args.test)
        failed_attempts = parse_log(args.file)
        print_alerts(
            failed_attempts,
            threshold=args.threshold,
            use_geo=args.geo,
            do_save=args.save,
            do_block=args.block,
            show_stats=args.stats,
            alert_discord=args.alert
        )
        return
    if args.live:
        track_live_log(
            file_path=args.file,
            threshold=args.threshold,
            use_geo=args.geo,
            do_save=args.save,
            do_block=args.block,
            alert_discord=args.alert
        )
        return
    failed_attempts = parse_log(args.file)
    print_alerts(
        failed_attempts,
        args.threshold,
        use_geo=args.geo,
        do_save=args.save,
        do_block=args.block,
        show_stats=args.stats,
        alert_discord=args.alert
    )

if __name__ == "__main__":
    main()
 