"""
Import service — CSV upload, validation, and staging pipeline.

Rules enforced (SRS §5.2, FR-IMP-001 to FR-IMP-004):
- Rows enter STAGED status and are never visible in the member-facing directory.
- Required fields are validated; malformed/duplicate rows are rejected with reasons.
- Email is normalised (lowercase, trimmed) and checked for duplicates both
  within the file and against existing member records.
- Import-run metadata (uploader, filename, timestamp, row outcomes) is always preserved.
"""
import csv
import io
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.logging import get_logger
from app.repositories.import_runs_repo import ImportRunsRepository
from app.repositories.members_repo import MembersRepository

logger = get_logger(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Columns accepted from the CSV. Only 'name' and 'email' are required;
# everything else is optional profile data.
REQUIRED_FIELDS = ["name", "email"]
OPTIONAL_FIELDS = [
    "phone", "gender", "dob", "state", "city", "pincode",
    "sub_caste", "marital_status", "occupation", "organisation",
    "education_sector", "blood_group", "about",
]
ALL_FIELDS = REQUIRED_FIELDS + OPTIONAL_FIELDS


@dataclass
class RowError:
    row_number: int
    reason: str
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportResult:
    total_rows: int
    valid_rows: int
    invalid_rows: int
    errors: List[Dict[str, Any]]
    staged_member_ids: List[str]  # internal Mongo _id strings of newly staged records
    import_run_id: str


def _normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def _normalize_row(raw_row: Dict[str, str]) -> Dict[str, str]:
    """Normalize keys to lowercase/underscore and strip whitespace from values."""
    normalized = {}
    for key, value in raw_row.items():
        if key is None:
            continue
        norm_key = key.strip().lower().replace(" ", "_")
        normalized[norm_key] = (value or "").strip()
    return normalized


def _validate_row(row: Dict[str, str], row_number: int) -> Optional[str]:
    """Return an error string if the row is invalid, else None."""
    name = row.get("name", "")
    email = row.get("email", "")

    if not name:
        return "Missing required field: name"
    if not email:
        return "Missing required field: email"
    if not EMAIL_RE.match(email):
        return f"Invalid email format: {email!r}"
    if len(name) > 200:
        return "Name exceeds maximum length (200 characters)"

    return None


def parse_csv(csv_text: str) -> List[Dict[str, str]]:
    """Parse CSV text into a list of normalized row dicts."""
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = []
    for raw_row in reader:
        normalized = _normalize_row(raw_row)
        # Skip fully blank rows
        if any(v for v in normalized.values()):
            rows.append(normalized)
    return rows


class ImportService:
    def __init__(self, db):
        self.db = db
        self.members_repo = MembersRepository(db)
        self.import_runs_repo = ImportRunsRepository(db)

    async def import_csv(
        self, csv_text: str, uploader_member_id: str, source_name: str
    ) -> ImportResult:
        rows = parse_csv(csv_text)
        total_rows = len(rows)

        errors: List[Dict[str, Any]] = []
        valid_candidates: List[Dict[str, Any]] = []
        seen_emails_in_file: Dict[str, int] = {}

        for i, row in enumerate(rows, start=1):
            reason = _validate_row(row, i)
            if reason:
                errors.append({"row_number": i, "reason": reason})
                continue

            email_normalized = _normalize_email(row["email"])

            # Duplicate within this same file
            if email_normalized in seen_emails_in_file:
                errors.append(
                    {
                        "row_number": i,
                        "reason": f"Duplicate email within file (first seen at row "
                        f"{seen_emails_in_file[email_normalized]})",
                    }
                )
                continue

            # Duplicate against existing records (STAGED, PENDING_ENROLLMENT, ACTIVE, etc.)
            existing = await self.members_repo.find_by_email(email_normalized)
            if existing:
                errors.append(
                    {
                        "row_number": i,
                        "reason": f"Email already exists in system (status: "
                        f"{existing.get('status', 'unknown')})",
                    }
                )
                continue

            seen_emails_in_file[email_normalized] = i

            profile = {k: row.get(k, "") for k in OPTIONAL_FIELDS}
            record = {
                "registered_email_normalized": email_normalized,
                "registered_email": row["email"].strip(),
                "role": "member",
                "profile": {
                    "name": row["name"].strip(),
                    **profile,
                },
                "visibility_settings": {},
                "import_row_number": i,
            }
            valid_candidates.append(record)

        # Insert all valid candidates as STAGED
        staged_ids: List[str] = []
        for record in valid_candidates:
            try:
                inserted_id = await self.members_repo.insert_staged(record)
                staged_ids.append(inserted_id)
            except Exception as exc:
                # e.g. unique index race condition on registered_email_normalized
                logger.warning("Failed to stage row %s: %s", record.get("import_row_number"), exc)
                errors.append(
                    {
                        "row_number": record.get("import_row_number"),
                        "reason": "Could not stage record (possible duplicate race condition)",
                    }
                )

        valid_rows = len(staged_ids)
        invalid_rows = total_rows - valid_rows

        import_run_id = await self.import_runs_repo.create_run(
            uploader_id=uploader_member_id,
            source_name=source_name,
            total_rows=total_rows,
            valid_rows=valid_rows,
            invalid_rows=invalid_rows,
            errors=errors,
        )

        logger.info(
            "Import run %s: %d total, %d staged, %d rejected",
            import_run_id, total_rows, valid_rows, invalid_rows,
        )

        return ImportResult(
            total_rows=total_rows,
            valid_rows=valid_rows,
            invalid_rows=invalid_rows,
            errors=errors,
            staged_member_ids=staged_ids,
            import_run_id=import_run_id,
        )
