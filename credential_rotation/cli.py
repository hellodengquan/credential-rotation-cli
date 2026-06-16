import typer
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

from .models import Credential, CredentialStatus
from .rotation import RotationManager
from .storage import Storage
from . import exporter


app = typer.Typer(
    name="credrot",
    help="密钥轮换管理 CLI 工具 - 管理凭证、跟踪到期日、生成轮换清单",
    add_completion=False,
)
console = Console()


def _get_manager(storage_path: Optional[Path] = None) -> RotationManager:
    storage = Storage(storage_path) if storage_path else Storage()
    return RotationManager(storage)


@app.command()
def register(
    cred_id: str = typer.Option(..., "--id", "-i", help="凭证唯一 ID"),
    name: str = typer.Option(..., "--name", "-n", help="凭证名称"),
    cred_type: str = typer.Option("api_key", "--type", "-t", help="凭证类型"),
    created: str = typer.Option(None, "--created", help="创建日期 (YYYY-MM-DD)"),
    expires: str = typer.Option(..., "--expires", "-e", help="到期日期 (YYYY-MM-DD)"),
    rotation_days: int = typer.Option(90, "--rotation-days", help="轮换周期天数"),
    warning_days: int = typer.Option(14, "--warning-days", help="提前警告天数"),
    description: Optional[str] = typer.Option(None, "--desc", help="描述"),
    owner: Optional[str] = typer.Option(None, "--owner", "-o", help="负责人"),
    tags: Optional[List[str]] = typer.Option(None, "--tag", help="标签 (可多次指定)"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
):
    """登记一个新凭证"""
    try:
        expires_at = datetime.strptime(expires, "%Y-%m-%d")
        expires_at = expires_at.replace(hour=23, minute=59, second=59)
    except ValueError:
        typer.secho(f"错误: 到期日期格式无效 '{expires}'，请使用 YYYY-MM-DD 格式", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if created:
        try:
            created_at = datetime.strptime(created, "%Y-%m-%d")
        except ValueError:
            typer.secho(f"错误: 创建日期格式无效 '{created}'，请使用 YYYY-MM-DD 格式", fg=typer.colors.RED)
            raise typer.Exit(code=1)
    else:
        created_at = datetime.now()

    credential = Credential(
        id=cred_id,
        name=name,
        type=cred_type,
        created_at=created_at,
        expires_at=expires_at,
        rotation_period_days=rotation_days,
        warning_days=warning_days,
        description=description,
        owner=owner,
        tags=tags or [],
    )

    manager = _get_manager(storage_path)
    try:
        manager.add_credential(credential)
    except ValueError as e:
        typer.secho(f"错误: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    days_left = credential.days_until_expiry()
    console.print(Panel.fit(
        f"[green]✓ 凭证登记成功[/green]\n\n"
        f"ID:           {credential.id}\n"
        f"名称:         {credential.name}\n"
        f"类型:         {credential.type}\n"
        f"到期日期:     {credential.expires_at.strftime('%Y-%m-%d')}\n"
        f"剩余天数:     {days_left} 天\n"
        f"警告提前:     {credential.warning_days} 天\n"
        f"轮换周期:     {credential.rotation_period_days} 天",
        title="凭证登记",
        border_style="green"
    ))


@app.command("list")
def list_credentials(
    status_filter: Optional[str] = typer.Option(None, "--status", "-s",
                                                help="按状态筛选: active/expiring_soon/expired/rotated"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
):
    """列出所有凭证"""
    manager = _get_manager(storage_path)
    creds = manager.get_all_credentials()

    if status_filter:
        try:
            status_enum = CredentialStatus(status_filter)
            creds = [c for c in creds if c.status == status_enum]
        except ValueError:
            typer.secho(f"错误: 无效的状态 '{status_filter}'", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    if not creds:
        console.print("[yellow]暂无凭证记录[/yellow]")
        return

    table = Table(title="凭证列表", show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("名称", style="white")
    table.add_column("类型", style="blue")
    table.add_column("状态", style="bold")
    table.add_column("到期日期", style="yellow")
    table.add_column("剩余天数", justify="right")
    table.add_column("负责人", style="magenta")

    for cred in sorted(creds, key=lambda c: c.expires_at):
        status_style = _get_status_style(cred.status)
        status_text = _translate_status(cred.status.value)
        days_left = cred.days_until_expiry()

        if cred.status == CredentialStatus.EXPIRED:
            days_text = Text(f"{days_left}", style="red")
        elif cred.status == CredentialStatus.EXPIRING_SOON:
            days_text = Text(f"{days_left}", style="yellow")
        else:
            days_text = Text(f"{days_left}", style="green")

        table.add_row(
            cred.id,
            cred.name,
            cred.type,
            Text(status_text, style=status_style),
            cred.expires_at.strftime("%Y-%m-%d"),
            days_text,
            cred.owner or "-",
        )

    console.print(table)
    stats = manager.get_statistics()
    console.print(f"\n总计: {stats['total']} 个 | "
                  f"[green]正常: {stats['active']}[/green] | "
                  f"[yellow]即将到期: {stats['expiring_soon']}[/yellow] | "
                  f"[red]已过期: {stats['expired']}[/red] | "
                  f"[blue]已轮换: {stats['rotated']}[/blue]")


@app.command()
def warn(
    days: int = typer.Option(None, "--days", "-d", help="指定天数内到期的凭证"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
):
    """显示即将到期/已过期的凭证警告"""
    manager = _get_manager(storage_path)
    expiring = manager.get_expiring_credentials(within_days=days)

    if not expiring:
        console.print(Panel("[green]✓ 所有凭证状态正常，没有即将到期的凭证[/green]",
                           title="凭证状态检查", border_style="green"))
        return

    title = f"⚠️  警告: {len(expiring)} 个凭证需要关注"
    if days:
        title += f" (未来 {days} 天内)"

    table = Table(title=title, show_lines=True, title_style="bold red")
    table.add_column("优先级", style="bold", justify="center")
    table.add_column("ID", style="cyan")
    table.add_column("名称", style="white")
    table.add_column("状态", style="bold")
    table.add_column("到期日期", style="yellow")
    table.add_column("剩余天数", justify="right")
    table.add_column("建议操作", style="magenta")
    table.add_column("负责人", style="blue")

    for cred in expiring:
        action = manager.get_action_for_credential(cred)
        action_text = _translate_action(action.value)
        status_text = _translate_status(cred.status.value)
        status_style = _get_status_style(cred.status)

        if cred.is_expired():
            priority = Text("紧急", style="bold red")
        elif cred.days_until_expiry() <= 7:
            priority = Text("高", style="bold yellow")
        else:
            priority = Text("中", style="bold blue")

        table.add_row(
            priority,
            cred.id,
            cred.name,
            Text(status_text, style=status_style),
            cred.expires_at.strftime("%Y-%m-%d"),
            str(cred.days_until_expiry()),
            action_text,
            cred.owner or "-",
        )

    console.print(table)

    expired_count = sum(1 for c in expiring if c.status == CredentialStatus.EXPIRED)
    if expired_count > 0:
        console.print(f"\n[red]⚠️  有 {expired_count} 个凭证已过期，请立即处理！[/red]")


@app.command()
def rotate(
    cred_id: str = typer.Argument(..., help="要标记为已轮换的凭证 ID"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
):
    """标记凭证为已轮换"""
    manager = _get_manager(storage_path)
    try:
        cred = manager.mark_as_rotated(cred_id)
    except ValueError as e:
        typer.secho(f"错误: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    console.print(Panel.fit(
        f"[green]✓ 凭证已标记为轮换[/green]\n\n"
        f"ID:       {cred.id}\n"
        f"名称:     {cred.name}\n"
        f"轮换时间: {cred.last_rotated_at.strftime('%Y-%m-%d %H:%M:%S') if cred.last_rotated_at else 'N/A'}",
        title="凭证轮换",
        border_style="green"
    ))


@app.command()
def export(
    output: Path = typer.Option(..., "--output", "-o", help="输出文件路径"),
    format: str = typer.Option("json", "--format", "-f", help="导出格式: json/csv/markdown"),
    include_expired: bool = typer.Option(True, "--include-expired/--no-expired", help="包含已过期凭证"),
    include_expiring: bool = typer.Option(True, "--include-expiring/--no-expiring", help="包含即将到期凭证"),
    include_active: bool = typer.Option(False, "--include-active/--no-active", help="包含正常凭证"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
):
    """导出轮换清单"""
    manager = _get_manager(storage_path)
    rotation_list = manager.generate_rotation_list(
        include_expired=include_expired,
        include_expiring=include_expiring,
        include_active=include_active,
    )

    format_lower = format.lower()
    if format_lower == "json":
        exporter.export_to_json(rotation_list, output)
    elif format_lower == "csv":
        exporter.export_to_csv(rotation_list, output)
    elif format_lower in ("md", "markdown"):
        exporter.export_to_markdown(rotation_list, output)
    else:
        typer.secho(f"错误: 不支持的格式 '{format}'，支持: json, csv, markdown", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    console.print(f"[green]✓ 轮换清单已导出到: {output}[/green]")
    console.print(f"共 {len(rotation_list)} 个凭证")


@app.command()
def stats(
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
):
    """显示凭证统计信息"""
    manager = _get_manager(storage_path)
    stats = manager.get_statistics()

    table = Table(title="凭证统计", show_header=False)
    table.add_column("项目", style="cyan")
    table.add_column("数量", justify="right", style="bold")

    table.add_row("总凭证数", str(stats["total"]))
    table.add_row("正常", f"[green]{stats['active']}[/green]")
    table.add_row("即将到期", f"[yellow]{stats['expiring_soon']}[/yellow]")
    table.add_row("已过期", f"[red]{stats['expired']}[/red]")
    table.add_row("已轮换", f"[blue]{stats['rotated']}[/blue]")

    console.print(table)

    if stats["by_type"]:
        type_table = Table(title="按类型统计", show_header=False)
        type_table.add_column("类型", style="cyan")
        type_table.add_column("数量", justify="right")
        for cred_type, count in sorted(stats["by_type"].items()):
            type_table.add_row(cred_type, str(count))
        console.print(type_table)


def _get_status_style(status: CredentialStatus) -> str:
    mapping = {
        CredentialStatus.ACTIVE: "green",
        CredentialStatus.EXPIRING_SOON: "yellow",
        CredentialStatus.EXPIRED: "red",
        CredentialStatus.ROTATED: "blue",
    }
    return mapping.get(status, "white")


def _translate_status(status: str) -> str:
    mapping = {
        "active": "正常",
        "expiring_soon": "即将到期",
        "expired": "已过期",
        "rotated": "已轮换",
    }
    return mapping.get(status, status)


def _translate_action(action: str) -> str:
    mapping = {
        "rotate_now": "立即轮换",
        "schedule_soon": "尽快安排",
        "monitor": "持续监控",
        "no_action": "无需操作",
    }
    return mapping.get(action, action)


if __name__ == "__main__":
    app()
