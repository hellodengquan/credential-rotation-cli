from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import exporter, importer
from .models import (
    TYPE_CONFIG_DESCRIPTIONS,
    Credential,
    CredentialStatus,
    get_type_config,
    get_type_registry,
)
from .remote import fetch_remote, is_remote_path
from .rotation import RotationManager
from .storage import Storage

app = typer.Typer(
    name="credrot",
    help="密钥轮换管理 CLI 工具 - 管理凭证、跟踪到期日、生成轮换清单",
    add_completion=False,
)
console = Console()


def _get_manager(
    storage_path: Optional[Path] = None,
    use_keyring: bool = False,
    vault_backend: Optional[str] = None,
) -> RotationManager:
    if vault_backend and vault_backend != "keyring":
        storage = Storage(storage_path, use_keyring=False)
    else:
        storage = Storage(storage_path, use_keyring=use_keyring)
    return RotationManager(storage)


@app.command()
def register(
    cred_id: str = typer.Option(..., "--id", "-i", help="凭证唯一 ID"),
    name: str = typer.Option(..., "--name", "-n", help="凭证名称"),
    cred_type: str = typer.Option("api_key", "--type", "-t", help="凭证类型"),
    created: str = typer.Option(None, "--created", help="创建日期 (YYYY-MM-DD)"),
    expires: str = typer.Option(..., "--expires", "-e", help="到期日期 (YYYY-MM-DD)"),
    rotation_days: int = typer.Option(0, "--rotation-days", help="轮换周期天数 (默认按类型自动)"),
    warning_days: int = typer.Option(0, "--warning-days", help="提前警告天数 (默认按类型自动)"),
    description: Optional[str] = typer.Option(None, "--desc", help="描述"),
    owner: Optional[str] = typer.Option(None, "--owner", "-o", help="负责人"),
    service: Optional[str] = typer.Option(None, "--service", help="所属服务"),
    environment: Optional[str] = typer.Option(None, "--env", help="环境 (prod/staging/dev)"),
    secret_value: Optional[str] = typer.Option(None, "--secret", help="敏感值"),
    tags: Optional[list[str]] = typer.Option(None, "--tag", help="标签 (可多次指定)"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
    use_keyring: bool = typer.Option(False, "--keyring", help="使用 keyring 加密敏感字段"),
    dry_run: bool = typer.Option(False, "--dry-run", help="仅预览不实际写入"),
):
    """登记一个新凭证"""
    try:
        expires_at = datetime.strptime(expires, "%Y-%m-%d")
        expires_at = expires_at.replace(hour=23, minute=59, second=59)
    except ValueError:
        typer.secho(
            f"错误: 到期日期格式无效 '{expires}'，请使用 YYYY-MM-DD 格式", fg=typer.colors.RED
        )
        raise typer.Exit(code=1)

    if created:
        try:
            created_at = datetime.strptime(created, "%Y-%m-%d")
        except ValueError:
            typer.secho(
                f"错误: 创建日期格式无效 '{created}'，请使用 YYYY-MM-DD 格式", fg=typer.colors.RED
            )
            raise typer.Exit(code=1)
    else:
        created_at = datetime.now()

    cfg = get_type_config(cred_type)
    final_rotation_days = rotation_days if rotation_days > 0 else cfg["rotation_period_days"]
    final_warning_days = warning_days if warning_days > 0 else cfg["warning_days"]

    credential = Credential(
        id=cred_id,
        name=name,
        type=cred_type,
        created_at=created_at,
        expires_at=expires_at,
        rotation_period_days=final_rotation_days,
        warning_days=final_warning_days,
        description=description,
        owner=owner,
        service=service,
        environment=environment,
        secret_value=secret_value,
        tags=tags or [],
    )

    if dry_run:
        console.print(
            Panel.fit(
                f"[yellow]🔍 DRY RUN 预览模式[/yellow]\n\n"
                f"ID:           {credential.id}\n"
                f"名称:         {credential.name}\n"
                f"类型:         {credential.type}\n"
                f"服务:         {credential.service or '(未指定)'}\n"
                f"环境:         {credential.environment or '(未指定)'}\n"
                f"到期日期:     {credential.expires_at.strftime('%Y-%m-%d')}\n"
                f"剩余天数:     {credential.days_until_expiry()} 天\n"
                f"警告提前:     {credential.warning_days} 天\n"
                f"轮换周期:     {credential.rotation_period_days} 天",
                title="凭证登记 [DRY RUN]",
                border_style="yellow",
            )
        )
        return

    manager = _get_manager(storage_path, use_keyring=use_keyring)
    try:
        manager.add_credential(credential)
    except ValueError as e:
        typer.secho(f"错误: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    days_left = credential.days_until_expiry()
    console.print(
        Panel.fit(
            f"[green]✓ 凭证登记成功[/green]\n\n"
            f"ID:           {credential.id}\n"
            f"名称:         {credential.name}\n"
            f"类型:         {credential.type}\n"
            f"服务:         {credential.service or '(未指定)'}\n"
            f"环境:         {credential.environment or '(未指定)'}\n"
            f"到期日期:     {credential.expires_at.strftime('%Y-%m-%d')}\n"
            f"剩余天数:     {days_left} 天",
            title="凭证登记",
            border_style="green",
        )
    )


@app.command("import", help="从 CSV 文件批量导入凭证 (支持 s3:// 和 sftp:// 远端路径)")
def import_csv(
    csv_file: str = typer.Argument(
        ..., help="CSV 文件路径 (本地或 s3://bucket/key, sftp://host/path)"
    ),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
    use_keyring: bool = typer.Option(False, "--keyring", help="使用 keyring 加密敏感字段"),
    dry_run: bool = typer.Option(False, "--dry-run", help="仅预览不实际写入"),
    on_conflict_skip: bool = typer.Option(
        True, "--skip-existing/--error-existing", help="ID 冲突时跳过/报错"
    ),
    s3_endpoint: Optional[str] = typer.Option(None, "--s3-endpoint", help="S3 兼容端点 URL"),
    s3_region: Optional[str] = typer.Option(None, "--s3-region", help="S3 区域"),
    sftp_host: Optional[str] = typer.Option(None, "--sftp-host", help="SFTP 主机"),
    sftp_port: int = typer.Option(22, "--sftp-port", help="SFTP 端口"),
    sftp_user: Optional[str] = typer.Option(None, "--sftp-user", help="SFTP 用户名"),
    sftp_key: Optional[str] = typer.Option(None, "--sftp-key", help="SFTP 私钥路径"),
):
    """从 CSV 文件批量导入凭证 (支持本地/S3/SFTP)"""
    local_csv_path: Path

    if is_remote_path(csv_file):
        console.print(f"[cyan]正在从远端拉取: {csv_file}[/cyan]")
        try:
            if csv_file.startswith("s3://"):
                kwargs: dict = {}
                if s3_endpoint:
                    kwargs["endpoint_url"] = s3_endpoint
                if s3_region:
                    kwargs["region"] = s3_region
                local_csv_path = fetch_remote(csv_file, **kwargs)
            elif csv_file.startswith("sftp://"):
                if not sftp_host:
                    sftp_host = csv_file.split("//", 1)[1].split("/")[0]
                kwargs = {"host": sftp_host, "port": sftp_port}
                if sftp_user:
                    kwargs["username"] = sftp_user
                if sftp_key:
                    kwargs["key_filename"] = sftp_key
                "/" + csv_file.split("//", 1)[1].split("/", 1)[1] if "/" in csv_file.split("//", 1)[
                    1
                ] else csv_file
                local_csv_path = fetch_remote(csv_file, **kwargs)
            else:
                local_csv_path = fetch_remote(csv_file)
        except ImportError as e:
            typer.secho(f"错误: 远端拉取需要额外依赖 - {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        except Exception as e:
            typer.secho(f"错误: 远端拉取失败 - {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        console.print("[green]✓ 远端文件已拉取到本地[/green]")
    else:
        local_csv_path = Path(csv_file)
        if not local_csv_path.exists():
            typer.secho(f"错误: 文件不存在 '{csv_file}'", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    credentials, errors = importer.parse_csv_import(local_csv_path)

    if errors:
        err_table = Table(title=f"⚠️  发现 {len(errors)} 行解析错误", title_style="bold red")
        err_table.add_column("行号", style="yellow", justify="right")
        err_table.add_column("ID", style="cyan")
        err_table.add_column("错误", style="red")
        for err in errors:
            err_table.add_row(str(err["row"]), err["id"] or "(空)", err["error"])
        console.print(err_table)

    if not credentials:
        console.print("[yellow]没有可导入的有效凭证[/yellow]")
        return

    manager = _get_manager(storage_path, use_keyring=use_keyring)

    if dry_run:
        dry_table = Table(
            title=f"🔍 DRY RUN - 将导入 {len(credentials)} 个凭证", title_style="bold yellow"
        )
        dry_table.add_column("ID", style="cyan")
        dry_table.add_column("名称", style="white")
        dry_table.add_column("类型", style="blue")
        dry_table.add_column("到期日期", style="yellow")
        dry_table.add_column("服务", style="magenta")
        dry_table.add_column("环境", style="green")
        for c in credentials:
            dry_table.add_row(
                c.id,
                c.name,
                c.type,
                c.expires_at.strftime("%Y-%m-%d"),
                c.service or "-",
                c.environment or "-",
            )
        console.print(dry_table)
        return

    added: list[Credential] = []
    skipped: list[str] = []
    failed: list[str] = []

    for c in credentials:
        existing = manager.get_credential(c.id)
        if existing:
            if on_conflict_skip:
                skipped.append(c.id)
                continue
            else:
                failed.append(f"{c.id}: ID 已存在")
                continue
        try:
            manager.add_credential(c)
            added.append(c)
        except Exception as e:
            failed.append(f"{c.id}: {e}")

    lines = []
    if added:
        lines.append(f"[green]✓ 成功导入 {len(added)} 个凭证[/green]")
    if skipped:
        lines.append(f"[yellow]⏭  跳过 {len(skipped)} 个已存在的 ID: {', '.join(skipped)}[/yellow]")
    if failed:
        lines.append(f"[red]✗ 失败 {len(failed)} 个:")
        for f in failed:
            lines.append(f"[red]  - {f}[/red]")
    console.print(Panel("\n".join(lines), title="批量导入结果"))


@app.command("template")
def generate_template(
    output: Path = typer.Argument(..., help="输出 CSV 模板文件路径"),
):
    """生成 CSV 导入模板文件"""
    path = importer.generate_csv_template(output)
    console.print(f"[green]✓ 模板已生成: {path}[/green]")


@app.command("list")
def list_credentials(
    status_filter: Optional[str] = typer.Option(
        None, "--status", "-s", help="按状态筛选: active/expiring_soon/expired/rotated"
    ),
    service_filter: Optional[str] = typer.Option(None, "--service", help="按服务筛选"),
    env_filter: Optional[str] = typer.Option(None, "--env", help="按环境筛选"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
    use_keyring: bool = typer.Option(False, "--keyring", help="使用 keyring 解密敏感字段"),
):
    """列出所有凭证"""
    manager = _get_manager(storage_path, use_keyring=use_keyring)
    creds = manager.get_all_credentials()

    if status_filter:
        try:
            status_enum = CredentialStatus(status_filter)
            creds = [c for c in creds if c.status == status_enum]
        except ValueError:
            typer.secho(f"错误: 无效的状态 '{status_filter}'", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    if service_filter:
        creds = [c for c in creds if (c.service or "").lower() == service_filter.lower()]

    if env_filter:
        creds = [c for c in creds if (c.environment or "").lower() == env_filter.lower()]

    if not creds:
        console.print("[yellow]暂无凭证记录[/yellow]")
        return

    conflicts = {c.credential_id for c in manager.detect_concurrent_rotation_conflicts(creds)}

    table = Table(title="凭证列表", show_lines=True)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("名称", style="white")
    table.add_column("类型", style="blue")
    table.add_column("服务", style="magenta")
    table.add_column("环境", style="green")
    table.add_column("状态", style="bold")
    table.add_column("到期日期", style="yellow")
    table.add_column("剩余天数", justify="right")
    table.add_column("负责人", style="blue")
    table.add_column("冲突", justify="center", style="bold")

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

        conflict_mark = (
            Text("⚠", style="bold red") if cred.id in conflicts else Text("-", style="dim")
        )

        table.add_row(
            cred.id,
            cred.name,
            cred.type,
            cred.service or "-",
            cred.environment or "-",
            Text(status_text, style=status_style),
            cred.expires_at.strftime("%Y-%m-%d"),
            days_text,
            cred.owner or "-",
            conflict_mark,
        )

    console.print(table)
    stats = manager.get_statistics()
    summary = (
        f"\n总计: {stats['total']} 个 | "
        f"[green]正常: {stats['active']}[/green] | "
        f"[yellow]即将到期: {stats['expiring_soon']}[/yellow] | "
        f"[red]已过期: {stats['expired']}[/red] | "
        f"[blue]已轮换: {stats['rotated']}[/blue]"
    )
    if int(stats["conflicts"]) > 0:  # type: ignore[call-overload]
        summary += f" | [red]⚠ 冲突: {stats['conflicts']}[/red]"
    console.print(summary)


@app.command()
def warn(
    days: int = typer.Option(None, "--days", "-d", help="指定天数内到期的凭证"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
    use_keyring: bool = typer.Option(False, "--keyring", help="使用 keyring 解密敏感字段"),
):
    """显示即将到期/已过期的凭证警告"""
    manager = _get_manager(storage_path, use_keyring=use_keyring)
    expiring = manager.get_expiring_credentials(within_days=days)

    if not expiring:
        console.print(
            Panel(
                "[green]✓ 所有凭证状态正常，没有即将到期的凭证[/green]",
                title="凭证状态检查",
                border_style="green",
            )
        )
        return

    title = f"⚠️  警告: {len(expiring)} 个凭证需要关注"
    if days:
        title += f" (未来 {days} 天内)"

    all_confs = manager.detect_concurrent_rotation_conflicts()
    {c.credential_id for c in all_confs}

    table = Table(title=title, show_lines=True, title_style="bold red")
    table.add_column("优先级", style="bold", justify="center")
    table.add_column("ID", style="cyan")
    table.add_column("名称", style="white")
    table.add_column("服务", style="magenta")
    table.add_column("环境", style="green")
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
            cred.service or "-",
            cred.environment or "-",
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
    if all_confs:
        console.print(f"\n[red]⚠️  检测到 {len(all_confs)} 个并发轮换冲突[/red]")


@app.command()
def rotate(
    cred_id: str = typer.Argument(..., help="要标记为已轮换的凭证 ID"),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
    use_keyring: bool = typer.Option(False, "--keyring", help="使用 keyring 解密敏感字段"),
    dry_run: bool = typer.Option(False, "--dry-run", help="仅预览不实际写入"),
):
    """标记凭证为已轮换"""
    manager = _get_manager(storage_path, use_keyring=use_keyring)
    cred = manager.get_credential(cred_id)
    if not cred:
        typer.secho(f"错误: 凭证 '{cred_id}' 不存在", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if dry_run:
        console.print(
            Panel.fit(
                f"[yellow]🔍 DRY RUN 预览模式[/yellow]\n\n"
                f"ID:       {cred.id}\n"
                f"名称:     {cred.name}\n"
                f"当前状态: {_translate_status(cred.status.value)}\n"
                f"到期日期: {cred.expires_at.strftime('%Y-%m-%d')}\n\n"
                f"[dim]将被标记为已轮换 (ROTATED)[/dim]",
                title="凭证轮换 [DRY RUN]",
                border_style="yellow",
            )
        )
        return

    try:
        rotated = manager.mark_as_rotated(cred_id)
    except ValueError as e:
        typer.secho(f"错误: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    console.print(
        Panel.fit(
            f"[green]✓ 凭证已标记为轮换[/green]\n\n"
            f"ID:       {rotated.id}\n"
            f"名称:     {rotated.name}\n"
            f"轮换时间: {rotated.last_rotated_at.strftime('%Y-%m-%d %H:%M:%S') if rotated.last_rotated_at else 'N/A'}",
            title="凭证轮换",
            border_style="green",
        )
    )


@app.command()
def conflicts(
    window_days: int = typer.Option(1, "--window", "-w", help="到期间隔多少天内算冲突"),
    cross_environment: bool = typer.Option(
        False, "--cross-env/--isolate-env", help="跨环境检测 (默认环境隔离)"
    ),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
    use_keyring: bool = typer.Option(False, "--keyring", help="使用 keyring 解密敏感字段"),
):
    """检查同服务并发轮换冲突 (默认环境隔离)"""
    manager = _get_manager(storage_path, use_keyring=use_keyring)
    found = manager.detect_concurrent_rotation_conflicts(
        window_days=window_days,
        cross_environment=cross_environment,
    )

    if not found:
        mode = "跨环境" if cross_environment else "环境隔离"
        console.print(
            Panel(
                f"[green]✓ 未检测到并发轮换冲突 (窗口: {window_days} 天, 模式: {mode})[/green]",
                title="并发轮换冲突检查",
                border_style="green",
            )
        )
        return

    table = Table(
        title=f"⚠️  检测到 {len(found)} 个并发轮换冲突", title_style="bold red", show_lines=True
    )
    table.add_column("凭证 ID", style="cyan")
    table.add_column("服务", style="magenta")
    table.add_column("环境", style="green")
    table.add_column("到期日期", style="yellow")
    table.add_column("冲突凭证", style="red")
    table.add_column("详情", style="dim")

    cred_cache = {c.id: c for c in manager.get_all_credentials()}
    for conf in found:
        cred = cred_cache.get(conf.credential_id)
        exp = cred.expires_at.strftime("%Y-%m-%d") if cred else "?"
        table.add_row(
            conf.credential_id,
            conf.service or "-",
            conf.environment or "-",
            exp,
            ", ".join(conf.conflicting_ids),
            conf.details,
        )
    console.print(table)


@app.command()
def export(
    output: Path = typer.Option(..., "--output", "-o", help="输出文件路径"),
    format: str = typer.Option("json", "--format", "-f", help="导出格式: json/csv/markdown/ical"),
    include_expired: bool = typer.Option(
        True, "--include-expired/--no-expired", help="包含已过期凭证"
    ),
    include_expiring: bool = typer.Option(
        True, "--include-expiring/--no-expiring", help="包含即将到期凭证"
    ),
    include_active: bool = typer.Option(False, "--include-active/--no-active", help="包含正常凭证"),
    check_conflicts: bool = typer.Option(
        True, "--check-conflicts/--no-conflicts", help="导出时包含并发轮换冲突信息"
    ),
    cross_environment: bool = typer.Option(
        False, "--cross-env/--isolate-env", help="跨环境冲突检测 (默认环境隔离)"
    ),
    timezone_id: Optional[str] = typer.Option(
        None, "--timezone", "--tz", help="iCal 时区 (如 Asia/Shanghai)"
    ),
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
    use_keyring: bool = typer.Option(False, "--keyring", help="使用 keyring 解密敏感字段"),
):
    """导出轮换清单"""
    manager = _get_manager(storage_path, use_keyring=use_keyring)
    rotation_list = manager.generate_rotation_list(
        include_expired=include_expired,
        include_expiring=include_expiring,
        include_active=include_active,
        check_conflicts=check_conflicts,
        cross_environment=cross_environment,
    )

    format_lower = format.lower()
    if format_lower == "json":
        exporter.export_to_json(rotation_list, output)
    elif format_lower == "csv":
        exporter.export_to_csv(rotation_list, output)
    elif format_lower in ("md", "markdown"):
        exporter.export_to_markdown(rotation_list, output)
    elif format_lower in ("ics", "ical", "calendar"):
        exporter.export_to_ical(rotation_list, output, timezone_id=timezone_id)
    else:
        typer.secho(
            f"错误: 不支持的格式 '{format}'，支持: json, csv, markdown, ical", fg=typer.colors.RED
        )
        raise typer.Exit(code=1)

    console.print(f"[green]✓ 轮换清单已导出到: {output}[/green]")
    console.print(f"共 {len(rotation_list)} 个凭证")


@app.command()
def stats(
    storage_path: Optional[Path] = typer.Option(None, "--storage", help="存储文件路径"),
    use_keyring: bool = typer.Option(False, "--keyring", help="使用 keyring 解密敏感字段"),
):
    """显示凭证统计信息"""
    manager = _get_manager(storage_path, use_keyring=use_keyring)
    stats_data = manager.get_statistics()

    table = Table(title="凭证统计", show_header=False)
    table.add_column("项目", style="cyan")
    table.add_column("数量", justify="right", style="bold")

    table.add_row("总凭证数", str(stats_data["total"]))
    table.add_row("正常", f"[green]{stats_data['active']}[/green]")
    table.add_row("即将到期", f"[yellow]{stats_data['expiring_soon']}[/yellow]")
    table.add_row("已过期", f"[red]{stats_data['expired']}[/red]")
    table.add_row("已轮换", f"[blue]{stats_data['rotated']}[/blue]")
    table.add_row(
        "并发轮换冲突",
        f"[red]{stats_data['conflicts']}[/red]"
        if int(stats_data["conflicts"]) > 0  # type: ignore[call-overload]
        else str(stats_data["conflicts"]),
    )

    console.print(table)

    if stats_data["by_type"]:
        type_table = Table(title="按类型统计", show_header=False)
        type_table.add_column("类型", style="cyan")
        type_table.add_column("数量", justify="right")
        for cred_type, count in sorted(stats_data["by_type"].items()):  # type: ignore[attr-defined]
            type_table.add_row(cred_type, str(count))
        console.print(type_table)

    if stats_data["by_service"]:
        svc_table = Table(title="按服务统计", show_header=False)
        svc_table.add_column("服务", style="magenta")
        svc_table.add_column("数量", justify="right")
        for svc, count in sorted(stats_data["by_service"].items()):  # type: ignore[attr-defined]
            svc_table.add_row(svc, str(count))
        console.print(svc_table)

    if stats_data.get("by_environment"):
        env_table = Table(title="按环境统计", show_header=False)
        env_table.add_column("环境", style="green")
        env_table.add_column("数量", justify="right")
        for env, count in sorted(stats_data["by_environment"].items()):  # type: ignore[attr-defined]
            env_table.add_row(env, str(count))
        console.print(env_table)


@app.command("type-configs")
def type_configs(
    detail: bool = typer.Option(False, "--detail", "-d", help="显示详细说明"),
    save_custom: bool = typer.Option(False, "--save", help="保存自定义配置到文件"),
):
    """查看/管理凭证类型的默认轮换/警告配置"""
    registry = get_type_registry()

    if save_custom:
        path = registry.save_custom()
        console.print(f"[green]✓ 自定义类型配置已保存到: {path}[/green]")

    table = Table(title="凭证类型配置")
    table.add_column("类型", style="cyan")
    table.add_column("轮换周期(天)", justify="right")
    table.add_column("警告提前(天)", justify="right")
    table.add_column("来源", justify="center")
    if detail:
        table.add_column("说明")

    from .models import _DEFAULT_TYPE_CONFIGS

    for ct, cfg in registry.list_all().items():
        source = "内置" if ct in _DEFAULT_TYPE_CONFIGS else "自定义"
        row = [ct, str(cfg["rotation_period_days"]), str(cfg["warning_days"]), source]
        if detail:
            row.append(TYPE_CONFIG_DESCRIPTIONS.get(ct, ""))
        table.add_row(*row)
    console.print(table)

    custom = registry.list_custom()
    if custom:
        console.print(f"\n[cyan]自定义类型: {', '.join(custom.keys())}[/cyan]")
    console.print(f"[dim]配置文件: {registry.save_custom.__module__}[/dim]")


@app.command("register-type")
def register_type(
    name: str = typer.Argument(..., help="自定义凭证类型名称"),
    rotation_days: int = typer.Option(..., "--rotation-days", "-r", help="轮换周期天数"),
    warning_days: int = typer.Option(..., "--warning-days", "-w", help="警告提前天数"),
    save: bool = typer.Option(True, "--save/--no-save", help="是否持久化到配置文件"),
):
    """注册自定义凭证类型"""
    registry = get_type_registry()
    registry.register(name, rotation_days, warning_days)
    if save:
        path = registry.save_custom()
        console.print(f"[green]✓ 自定义类型 '{name}' 已注册并保存[/green]")
        console.print(f"  轮换周期: {rotation_days} 天 | 警告提前: {warning_days} 天")
        console.print(f"  配置文件: {path}")
    else:
        console.print(f"[green]✓ 自定义类型 '{name}' 已注册 (仅本次会话)[/green]")


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
