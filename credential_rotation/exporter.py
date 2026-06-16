import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


def _build_rrule(
    freq: str = "YEARLY",
    interval: int = 1,
    count: Optional[int] = None,
    until: Optional[datetime] = None,
    by_month: Optional[str] = None,
    by_day: Optional[str] = None,
) -> str:
    parts = [f"FREQ={freq}", f"INTERVAL={interval}"]
    if count is not None:
        parts.append(f"COUNT={count}")
    if until is not None:
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        parts.append(f"UNTIL={until.strftime('%Y%m%dT%H%M%SZ')}")
    if by_month is not None:
        parts.append(f"BYMONTH={by_month}")
    if by_day is not None:
        parts.append(f"BYDAY={by_day}")
    return "RRULE:" + ";".join(parts)


def generate_recurring_dates(
    start_date: datetime,
    rotation_days: int,
    max_years: int = 5,
    end_date: Optional[datetime] = None,
) -> list[datetime]:
    dates: list[datetime] = []
    current = start_date
    if end_date is None:
        end_date = start_date.replace(year=start_date.year + max_years)
    year_end = start_date.year + max_years
    while current <= end_date and current.year <= year_end:
        dates.append(current)
        current = current + timedelta(days=rotation_days)
    return dates


def generate_rrule_from_rotation_days(rotation_days: int) -> str:
    if rotation_days >= 365 and rotation_days % 365 == 0:
        years = rotation_days // 365
        return _build_rrule(freq="YEARLY", interval=years)
    if rotation_days >= 90 and rotation_days % 90 == 0:
        quarters = rotation_days // 90
        return (
            _build_rrule(freq="YEARLY", interval=1, by_month="1,4,7,10")
            if quarters == 1
            else _build_rrule(freq="MONTHLY", interval=3)
        )
    if rotation_days >= 30 and rotation_days % 30 == 0:
        months = rotation_days // 30
        return _build_rrule(freq="MONTHLY", interval=months)
    if rotation_days >= 7 and rotation_days % 7 == 0:
        weeks = rotation_days // 7
        return _build_rrule(freq="WEEKLY", interval=weeks)
    return _build_rrule(freq="DAILY", interval=rotation_days)


def generate_weekly_rrule(
    interval: int = 1,
    by_day: str = "MO",
    count: Optional[int] = None,
    until: Optional[datetime] = None,
) -> str:
    return _build_rrule(freq="WEEKLY", interval=interval, by_day=by_day, count=count, until=until)


def generate_quarterly_rrule(
    by_month: str = "1,4,7,10",
    interval: int = 1,
    count: Optional[int] = None,
    until: Optional[datetime] = None,
) -> str:
    return _build_rrule(
        freq="YEARLY", interval=interval, by_month=by_month, count=count, until=until
    )


def generate_composite_recurrence_sample(
    start_date: datetime,
    weekly_interval: int = 2,
    quarterly_months: str = "1,4,7,10",
    years: int = 3,
) -> dict:
    weekly_rrule = generate_weekly_rrule(interval=weekly_interval)
    quarterly_rrule = generate_quarterly_rrule(by_month=quarterly_months)

    weekly_dates: list[datetime] = []
    current = start_date
    end = start_date.replace(year=start_date.year + years)
    while current <= end:
        weekly_dates.append(current)
        current = current + timedelta(weeks=weekly_interval)

    quarterly_dates: list[datetime] = []
    months = [int(m) for m in quarterly_months.split(",")]
    for y in range(start_date.year, start_date.year + years + 1):
        for m in months:
            d = datetime(y, m, start_date.day, start_date.hour, start_date.minute)
            if d >= start_date and d <= end:
                quarterly_dates.append(d)

    return {
        "start_date": start_date.isoformat(),
        "weekly_rrule": weekly_rrule,
        "quarterly_rrule": quarterly_rrule,
        "weekly_events": len(weekly_dates),
        "quarterly_events": len(quarterly_dates),
        "weekly_first_5": [d.isoformat() for d in weekly_dates[:5]],
        "quarterly_dates": [d.isoformat() for d in quarterly_dates],
        "years_covered": years,
    }


def generate_cross_year_recurrence_sample(
    start_date: datetime,
    rotation_days: int,
    years: int = 5,
) -> dict:
    dates = generate_recurring_dates(start_date, rotation_days, max_years=years)
    rrule = generate_rrule_from_rotation_days(rotation_days)
    by_year: dict[int, int] = {}
    for d in dates:
        by_year[d.year] = by_year.get(d.year, 0) + 1
    return {
        "start_date": start_date.isoformat(),
        "rotation_days": rotation_days,
        "rrule": rrule,
        "total_events": len(dates),
        "years_covered": sorted(by_year.keys()),
        "events_by_year": by_year,
        "first_5_dates": [d.isoformat() for d in dates[:5]],
        "last_5_dates": [d.isoformat() for d in dates[-5:]],
    }


def export_to_json(rotation_list: list[dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(rotation_list, f, indent=2, ensure_ascii=False)
    return output_path


def _flatten_conflict(item: dict) -> dict:
    row = dict(item)
    conflict = row.pop("conflict", None)
    if isinstance(conflict, dict):
        row["has_conflict"] = conflict.get("has_conflict", False)
        row["conflicting_ids"] = ";".join(conflict.get("conflicting_ids", []))
        row["conflict_details"] = conflict.get("details", "")
    else:
        row["has_conflict"] = False
        row["conflicting_ids"] = ""
        row["conflict_details"] = ""
    return row


def export_to_csv(rotation_list: list[dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not rotation_list:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("")
        return output_path

    fieldnames = [
        "id",
        "name",
        "type",
        "owner",
        "status",
        "expires_at",
        "days_until_expiry",
        "rotation_period_days",
        "warning_days",
        "action",
        "last_rotated_at",
        "description",
        "tags",
        "service",
        "environment",
        "has_conflict",
        "conflicting_ids",
        "conflict_details",
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in rotation_list:
            row = _flatten_conflict(item)
            if isinstance(row.get("tags"), list):
                row["tags"] = ";".join(row["tags"])
            row.setdefault("service", "")
            row.setdefault("environment", "")
            writer.writerow(row)
    return output_path


def export_to_markdown(rotation_list: list[dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append("# 凭证轮换清单")
    lines.append("")
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    if not rotation_list:
        lines.append("暂无需要轮换的凭证。")
    else:
        lines.append(f"共 **{len(rotation_list)}** 个凭证需要关注。")
        lines.append("")

        lines.append(
            "| ID | 名称 | 类型 | 环境 | 状态 | 到期时间 | 剩余天数 | 建议操作 | 负责人 | 服务 | 冲突 |"
        )
        lines.append(
            "|-----|------|------|------|------|----------|----------|----------|--------|------|------|"
        )

        for item in rotation_list:
            status = _translate_status(item["status"])
            action = _translate_action(item["action"])
            conflict_info = item.get("conflict", {})
            if isinstance(conflict_info, dict) and conflict_info.get("has_conflict"):
                conflict_text = "⚠ " + ", ".join(conflict_info.get("conflicting_ids", []))
            else:
                conflict_text = "-"
            lines.append(
                f"| {item['id']} | {item['name']} | {item['type']} | "
                f"{item.get('environment', '-') or '-'} | {status} | "
                f"{item['expires_at'][:10]} | {item['days_until_expiry']} | "
                f"{action} | {item['owner'] or '-'} | {item.get('service', '-') or '-'} | {conflict_text} |"
            )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return output_path


def _build_vtimezone(tzid: str) -> list[str]:
    lines = []
    lines.append("BEGIN:VTIMEZONE")
    lines.append(f"TZID:{tzid}")
    lines.append("BEGIN:STANDARD")
    lines.append("DTSTART:19700101T000000")
    lines.append("TZOFFSETFROM:+0000")
    lines.append("TZOFFSETTO:+0000")
    lines.append(f"TZNAME:{tzid}")
    lines.append("END:STANDARD")
    lines.append("END:VTIMEZONE")
    return lines


def export_to_ical(
    rotation_list: list[dict],
    output_path: Path,
    timezone_id: Optional[str] = None,
    include_rrule: bool = False,
    rrule_until_years: int = 5,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tzid = timezone_id or "UTC"

    lines = []
    lines.append("BEGIN:VCALENDAR")
    lines.append("VERSION:2.0")
    lines.append("PRODID:-//Credential Rotation Manager//CN")
    lines.append("CALSCALE:GREGORIAN")
    lines.append("METHOD:PUBLISH")
    lines.append(f"X-WR-TIMEZONE:{tzid}")

    if tzid != "UTC":
        lines.extend(_build_vtimezone(tzid))

    for item in rotation_list:
        expires_str = item.get("expires_at", "")
        try:
            expires_dt = datetime.fromisoformat(expires_str)
        except (ValueError, TypeError):
            continue

        expires_utc = expires_dt.astimezone(timezone.utc)
        dt_start = expires_utc.strftime("%Y%m%dT%H%M%SZ")
        dt_end = expires_utc.strftime("%Y%m%dT%H%M%SZ")
        dt_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        uid = f"{item['id']}@credential-rotation"
        status = _translate_status(item.get("status", ""))
        action = _translate_action(item.get("action", ""))
        environment = item.get("environment", "") or "N/A"
        summary = f"[{status}] {item['name']} ({item['type']}) 到期 [{environment}]"
        description_parts = [
            f"凭证ID: {item['id']}",
            f"类型: {item['type']}",
            f"状态: {status}",
            f"环境: {environment}",
            f"剩余天数: {item.get('days_until_expiry', 'N/A')}",
            f"建议操作: {action}",
            f"负责人: {item.get('owner') or 'N/A'}",
            f"服务: {item.get('service') or 'N/A'}",
            f"时区: {tzid}",
        ]
        conflict_info = item.get("conflict", {})
        if isinstance(conflict_info, dict) and conflict_info.get("has_conflict"):
            conflicting = ", ".join(conflict_info.get("conflicting_ids", []))
            description_parts.append(f"并发轮换冲突: {conflicting}")
            if conflict_info.get("details"):
                description_parts.append(f"冲突详情: {conflict_info['details']}")
        desc_text = "\\n".join(description_parts)

        lines.append("BEGIN:VEVENT")
        lines.append(f"UID:{uid}")
        lines.append(f"DTSTAMP:{dt_stamp}")
        if tzid == "UTC":
            lines.append(f"DTSTART:{dt_start}")
            lines.append(f"DTEND:{dt_end}")
        else:
            local_start = expires_dt.strftime("%Y%m%dT%H%M%S")
            lines.append(f"DTSTART;TZID={tzid}:{local_start}")
            lines.append(f"DTEND;TZID={tzid}:{local_start}")
        lines.append(f"SUMMARY:{summary}")
        lines.append(f"DESCRIPTION:{desc_text}")
        lines.append("STATUS:CONFIRMED")
        lines.append("TRANSP:OPAQUE")

        if include_rrule:
            rotation_days = int(item.get("rotation_period_days", 0))
            if rotation_days > 0:
                rrule_until = expires_utc.replace(year=expires_utc.year + rrule_until_years)
                rrule = _build_rrule(
                    freq="YEARLY"
                    if rotation_days >= 365
                    else "MONTHLY"
                    if rotation_days >= 30
                    else "WEEKLY"
                    if rotation_days >= 7
                    else "DAILY",
                    interval=max(
                        1,
                        rotation_days
                        // (
                            365
                            if rotation_days >= 365
                            else 30
                            if rotation_days >= 30
                            else 7
                            if rotation_days >= 7
                            else 1
                        ),
                    ),
                    until=rrule_until,
                )
                lines.append(rrule)

        lines.append("BEGIN:VALARM")
        lines.append("TRIGGER:-P14D")
        lines.append("ACTION:DISPLAY")
        lines.append(f"DESCRIPTION:凭证 {item['name']} 将在 14 天后到期")
        lines.append("END:VALARM")
        lines.append("BEGIN:VALARM")
        lines.append("TRIGGER:-P7D")
        lines.append("ACTION:DISPLAY")
        lines.append(f"DESCRIPTION:凭证 {item['name']} 将在 7 天后到期")
        lines.append("END:VALARM")
        lines.append("BEGIN:VALARM")
        lines.append("TRIGGER:-P1D")
        lines.append("ACTION:DISPLAY")
        lines.append(f"DESCRIPTION:凭证 {item['name']} 明天到期！")
        lines.append("END:VALARM")
        lines.append("END:VEVENT")

    lines.append("END:VCALENDAR")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\r\n".join(lines))
    return output_path


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
