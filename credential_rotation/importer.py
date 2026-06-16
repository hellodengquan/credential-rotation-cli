import csv
from datetime import datetime
from pathlib import Path

from .models import Credential, get_type_config

CSV_REQUIRED_FIELDS = ["id", "name", "type", "expires_at"]
CSV_OPTIONAL_FIELDS = [
    "created_at",
    "rotation_period_days",
    "warning_days",
    "description",
    "owner",
    "service",
    "environment",
    "secret_value",
    "tags",
]
CSV_ALL_FIELDS = CSV_REQUIRED_FIELDS + CSV_OPTIONAL_FIELDS


def parse_csv_import(csv_path: Path) -> tuple[list[Credential], list[dict]]:
    successful: list[Credential] = []
    errors: list[dict] = []

    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row_num, row in enumerate(reader, start=2):
            row = {k.strip(): v.strip() if v else "" for k, v in row.items()}

            missing = [f for f in CSV_REQUIRED_FIELDS if not row.get(f)]
            if missing:
                errors.append(
                    {
                        "row": row_num,
                        "id": row.get("id", ""),
                        "error": f"缺少必填字段: {', '.join(missing)}",
                    }
                )
                continue

            try:
                expires_at = _parse_date(row["expires_at"])
                if expires_at is None:
                    errors.append(
                        {
                            "row": row_num,
                            "id": row["id"],
                            "error": f"到期日期格式无效: {row['expires_at']}",
                        }
                    )
                    continue
                expires_at = expires_at.replace(hour=23, minute=59, second=59)

                created_at_str = row.get("created_at", "")
                if created_at_str:
                    created_at = _parse_date(created_at_str)
                    if created_at is None:
                        created_at = datetime.now()
                else:
                    created_at = datetime.now()

                cred_type = row.get("type", "api_key")
                type_config = get_type_config(cred_type)

                rotation_days = (
                    int(row["rotation_period_days"])
                    if row.get("rotation_period_days")
                    else type_config["rotation_period_days"]
                )
                warning_days = (
                    int(row["warning_days"])
                    if row.get("warning_days")
                    else type_config["warning_days"]
                )

                tags_str = row.get("tags", "")
                tags = [t.strip() for t in tags_str.split(";") if t.strip()] if tags_str else []

                credential = Credential(
                    id=row["id"],
                    name=row["name"],
                    type=cred_type,
                    created_at=created_at,
                    expires_at=expires_at,
                    rotation_period_days=rotation_days,
                    warning_days=warning_days,
                    description=row.get("description") or None,
                    owner=row.get("owner") or None,
                    service=row.get("service") or None,
                    environment=row.get("environment") or None,
                    secret_value=row.get("secret_value") or None,
                    tags=tags,
                )
                successful.append(credential)
            except Exception as e:
                errors.append(
                    {
                        "row": row_num,
                        "id": row.get("id", ""),
                        "error": str(e),
                    }
                )

    return successful, errors


def generate_csv_template(output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_ALL_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "id": "example-key-001",
                "name": "Example API Key",
                "type": "api_key",
                "expires_at": "2026-12-31",
                "created_at": "",
                "rotation_period_days": "",
                "warning_days": "",
                "description": "示例凭证",
                "owner": "team-xxx",
                "service": "aws",
                "environment": "prod",
                "secret_value": "",
                "tags": "prod;aws",
            }
        )
    return output_path


def _parse_date(date_str: str) -> datetime | None:
    date_str = date_str.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None
