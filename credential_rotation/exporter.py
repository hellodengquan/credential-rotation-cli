import csv
import json
from pathlib import Path
from typing import List, Dict


def export_to_json(rotation_list: List[Dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(rotation_list, f, indent=2, ensure_ascii=False)
    return output_path


def export_to_csv(rotation_list: List[Dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not rotation_list:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("")
        return output_path

    fieldnames = [
        "id", "name", "type", "owner", "status",
        "expires_at", "days_until_expiry", "rotation_period_days",
        "warning_days", "action", "last_rotated_at", "description", "tags"
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in rotation_list:
            row = dict(item)
            if isinstance(row.get("tags"), list):
                row["tags"] = ";".join(row["tags"])
            writer.writerow(row)
    return output_path


def export_to_markdown(rotation_list: List[Dict], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append("# 凭证轮换清单")
    lines.append("")
    lines.append(f"生成时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    if not rotation_list:
        lines.append("暂无需要轮换的凭证。")
    else:
        lines.append(f"共 **{len(rotation_list)}** 个凭证需要关注。")
        lines.append("")

        lines.append("| ID | 名称 | 类型 | 状态 | 到期时间 | 剩余天数 | 建议操作 | 负责人 |")
        lines.append("|-----|------|------|------|----------|----------|----------|--------|")

        for item in rotation_list:
            status = _translate_status(item["status"])
            action = _translate_action(item["action"])
            lines.append(
                f"| {item['id']} | {item['name']} | {item['type']} | {status} | "
                f"{item['expires_at'][:10]} | {item['days_until_expiry']} | "
                f"{action} | {item['owner'] or '-'} |"
            )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
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
