import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


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
