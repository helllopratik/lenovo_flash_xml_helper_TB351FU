#!/usr/bin/env python3
"""
Decrypt and validate Lenovo firmware metadata files without editing the source ROM.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

SIGNATURE_MAGIC = b"\xcf\x06\x05\x04\x03\x02\x01\xfc"
DEFAULT_PASSWORD = "OSD"
ITERATIONS = 1000
KEY_LENGTH = 32


try:
    from Crypto.Cipher import AES  # type: ignore
except ImportError as exc:  # pragma: no cover
    print(
        "Missing dependency: pycryptodome. Install it with:\n"
        "  python3 -m pip install pycryptodome",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc


class ValidationError(Exception):
    pass


def pbkdf1_custom(password: str, salt: bytes, length: int, iterations: int) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8") + salt).digest()
    for _ in range(1, iterations):
        digest = hashlib.sha256(digest).digest()
    return digest[:length]


def decrypt_lenovo_x_file(input_file: Path, output_file: Path, password: str) -> int:
    data = input_file.read_bytes()
    if len(data) < 32:
        raise ValidationError(f"{input_file} is too short to be a valid Lenovo .x file")

    iv = data[:16]
    salt = data[16:32]
    ciphertext = data[32:]

    if len(ciphertext) % 16 != 0:
        raise ValidationError(f"{input_file} ciphertext is not aligned to AES block size")

    key = pbkdf1_custom(password, salt, KEY_LENGTH, ITERATIONS)
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)

    original_size = struct.unpack("<Q", plain[:8])[0]
    signature = plain[8:16]
    if signature != SIGNATURE_MAGIC:
        raise ValidationError(
            f"{input_file} failed signature validation. Password may be wrong or file format differs."
        )

    body = plain[16 : 16 + original_size]
    hash_stored = plain[16 + original_size : 16 + original_size + 32]
    hash_calc = hashlib.sha256(body).digest()
    if hash_stored != hash_calc:
        raise ValidationError(f"{input_file} failed hash validation after decryption")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(body)
    return original_size


def parse_xml(path: Path) -> ET.ElementTree:
    try:
        return ET.parse(path)
    except ET.ParseError as exc:
        raise ValidationError(f"{path} is not valid XML: {exc}") from exc


def safe_hex_to_int(value: str, field_name: str, partition_name: str) -> int:
    try:
        if not value.lower().startswith("0x"):
            raise ValueError("hex value must start with 0x")
        return int(value, 16)
    except ValueError as exc:
        raise ValidationError(
            f"Partition '{partition_name}' has invalid {field_name}: {value}"
        ) from exc


def find_package_image_dir(package_dir: Path) -> Path:
    image_dir = package_dir / "image"
    if image_dir.is_dir():
        return image_dir
    raise ValidationError(f"Expected image directory not found: {image_dir}")


def find_existing_scatter_x(image_dir: Path, flash_scatter_name: Optional[str]) -> Optional[Path]:
    if flash_scatter_name:
        candidate = image_dir / flash_scatter_name.replace(".xml", ".x")
        if candidate.exists():
            return candidate

    preferred = sorted(image_dir.glob("*scatter*.x"))
    return preferred[0] if preferred else None


def validate_flash_xml(flash_xml: Path, image_dir: Path) -> Dict[str, str]:
    root = parse_xml(flash_xml).getroot()
    if root.tag != "flash-mode":
        raise ValidationError(f"{flash_xml} root tag must be 'flash-mode', found '{root.tag}'")

    project = (root.findtext("project") or "").strip()
    dagent = (root.findtext("dagent") or "").strip()
    scatter = (root.findtext("scatter") or "").strip()

    missing = [name for name, value in [("project", project), ("dagent", dagent), ("scatter", scatter)] if not value]
    if missing:
        raise ValidationError(f"{flash_xml} is missing required fields: {', '.join(missing)}")

    dagent_path = image_dir / dagent
    if not dagent_path.exists():
        raise ValidationError(f"DA file referenced by flash.xml does not exist: {dagent_path}")

    return {
        "project": project,
        "dagent": dagent,
        "scatter": scatter,
    }


def validate_scatter(scatter_xml: Path, image_dir: Path) -> Dict[str, object]:
    root = parse_xml(scatter_xml).getroot()
    if root.tag != "root":
        raise ValidationError(f"{scatter_xml} root tag must be 'root', found '{root.tag}'")

    storage_summaries: List[Dict[str, object]] = []
    referenced_files = set()
    address_warnings: List[str] = []
    partition_rows: List[Dict[str, str]] = []

    for storage_type in root.findall("storage_type"):
        storage_name = storage_type.attrib.get("name", "")
        partitions = storage_type.findall("partition_index")
        if not partitions:
            raise ValidationError(f"{scatter_xml} storage type '{storage_name}' has no partitions")

        last_linear = -1
        storage_summary = {
            "storage_type": storage_name,
            "partition_count": len(partitions),
            "downloadable_partition_count": 0,
            "first_partition": partitions[0].findtext("partition_name"),
            "last_partition": partitions[-1].findtext("partition_name"),
        }

        for partition in partitions:
            partition_name = (partition.findtext("partition_name") or "").strip()
            file_name = (partition.findtext("file_name") or "").strip()
            linear = (partition.findtext("linear_start_addr") or "").strip()
            physical = (partition.findtext("physical_start_addr") or "").strip()
            size = (partition.findtext("partition_size") or "").strip()

            if not partition_name:
                raise ValidationError(f"{scatter_xml} contains a partition with no partition_name")

            linear_val = safe_hex_to_int(linear, "linear_start_addr", partition_name)
            safe_hex_to_int(physical, "physical_start_addr", partition_name)
            size_val = safe_hex_to_int(size, "partition_size", partition_name)
            if size_val <= 0:
                raise ValidationError(f"Partition '{partition_name}' has non-positive size: {size}")

            if linear_val < last_linear:
                address_warnings.append(
                    f"{storage_name}: partition '{partition_name}' uses non-monotonic address {linear}"
                )
            last_linear = linear_val

            if file_name and file_name != "NONE":
                referenced_files.add(file_name)
                storage_summary["downloadable_partition_count"] += 1
                candidate = image_dir / file_name
                if not candidate.exists():
                    raise ValidationError(
                        f"Partition '{partition_name}' references missing file: {candidate}"
                    )

            partition_rows.append(
                {
                    "storage_type": storage_name,
                    "partition_name": partition_name,
                    "file_name": file_name,
                    "is_download": (partition.findtext("is_download") or "").strip(),
                    "type": (partition.findtext("type") or "").strip(),
                    "linear_start_addr": linear,
                    "physical_start_addr": physical,
                    "partition_size": size,
                    "region": (partition.findtext("region") or "").strip(),
                    "storage": (partition.findtext("storage") or "").strip(),
                    "boundary_check": (partition.findtext("boundary_check") or "").strip(),
                    "is_reserved": (partition.findtext("is_reserved") or "").strip(),
                    "operation_type": (partition.findtext("operation_type") or "").strip(),
                }
            )

        storage_summaries.append(storage_summary)

    return {
        "storage_types": storage_summaries,
        "referenced_files": sorted(referenced_files),
        "address_warnings": address_warnings,
        "partition_rows": partition_rows,
    }


def write_partition_exports(output_dir: Path, partition_rows: List[Dict[str, str]]) -> Dict[str, str]:
    csv_path = output_dir / "partition_summary.csv"
    json_path = output_dir / "partition_summary.json"
    txt_path = output_dir / "partition_summary.txt"

    fieldnames = [
        "storage_type",
        "partition_name",
        "file_name",
        "is_download",
        "type",
        "linear_start_addr",
        "physical_start_addr",
        "partition_size",
        "region",
        "storage",
        "boundary_check",
        "is_reserved",
        "operation_type",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(partition_rows)

    json_path.write_text(json.dumps(partition_rows, indent=2) + "\n", encoding="utf-8")

    lines = []
    header = (
        f"{'storage':<8} {'partition':<24} {'file':<22} "
        f"{'linear_start':<14} {'size':<14} {'region':<12}"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for row in partition_rows:
        lines.append(
            f"{row['storage_type']:<8} "
            f"{row['partition_name'][:24]:<24} "
            f"{row['file_name'][:22]:<22} "
            f"{row['linear_start_addr']:<14} "
            f"{row['partition_size']:<14} "
            f"{row['region']:<12}"
        )
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "partition_summary.csv": str(csv_path),
        "partition_summary.json": str(json_path),
        "partition_summary.txt": str(txt_path),
    }


def copy_support_files(image_dir: Path, output_dir: Path, flash_info: Dict[str, str]) -> Dict[str, str]:
    copied: Dict[str, str] = {}
    for name in ["flash.xsd", flash_info["dagent"], "da.auth"]:
        source = image_dir / name
        if source.exists():
            destination = output_dir / source.name
            shutil.copy2(source, destination)
            copied[source.name] = str(destination)
    return copied


def create_staging_folder(
    image_dir: Path,
    output_dir: Path,
    generated_files: Dict[str, str],
    copied_files: Dict[str, str],
    referenced_files: List[str],
    extra_files: Dict[str, str],
) -> Dict[str, object]:
    stage_dir = output_dir / "sp_flash_tool_bundle"
    stage_dir.mkdir(parents=True, exist_ok=True)

    staged: Dict[str, str] = {}

    for path_str in generated_files.values():
        source = Path(path_str)
        destination = stage_dir / source.name
        shutil.copy2(source, destination)
        staged[source.name] = str(destination)

    for path_str in copied_files.values():
        source = Path(path_str)
        destination = stage_dir / source.name
        if source.resolve() != destination.resolve():
            shutil.copy2(source, destination)
        staged[source.name] = str(destination)

    for path_str in extra_files.values():
        source = Path(path_str)
        destination = stage_dir / source.name
        if source.resolve() != destination.resolve():
            shutil.copy2(source, destination)
        staged[source.name] = str(destination)

    for file_name in referenced_files:
        source = image_dir / file_name
        destination = stage_dir / file_name
        shutil.copy2(source, destination)
        staged[file_name] = str(destination)

    return {
        "stage_dir": str(stage_dir),
        "staged_file_count": len(staged),
        "staged_files": staged,
    }


def build_report(
    package_dir: Path,
    image_dir: Path,
    output_dir: Path,
    flash_info: Dict[str, str],
    scatter_info: Dict[str, object],
    decrypted_sizes: Dict[str, int],
    copied_files: Dict[str, str],
    extra_outputs: Dict[str, str],
    partition_exports: Dict[str, str],
    stage_info: Dict[str, object],
) -> Dict[str, object]:
    return {
        "package_dir": str(package_dir),
        "image_dir": str(image_dir),
        "output_dir": str(output_dir),
        "project": flash_info["project"],
        "dagent": flash_info["dagent"],
        "scatter": flash_info["scatter"],
        "decrypted_sizes": decrypted_sizes,
        "copied_files": copied_files,
        "generated_files": extra_outputs,
        "partition_exports": partition_exports,
        "stage_info": stage_info,
        "scatter_summary": scatter_info["storage_types"],
        "referenced_image_files": scatter_info["referenced_files"],
        "address_warnings": scatter_info["address_warnings"],
        "warning": (
            "Validation confirms XML structure and package consistency only. "
            "It cannot guarantee a successful flash or device boot."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt and validate Lenovo flash metadata files")
    parser.add_argument("--package-dir", required=True, help="ROM folder that contains the image directory")
    parser.add_argument("--output-dir", required=True, help="Directory where decrypted files will be written")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Lenovo .x decryption password")
    args = parser.parse_args()

    package_dir = Path(args.package_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()

    try:
        image_dir = find_package_image_dir(package_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        flash_x = image_dir / "flash.x"
        if not flash_x.exists():
            raise ValidationError(f"Missing required file: {flash_x}")

        decrypted_sizes: Dict[str, int] = {}
        generated_files: Dict[str, str] = {}

        flash_xml = output_dir / "flash.xml"
        decrypted_sizes["flash.xml"] = decrypt_lenovo_x_file(flash_x, flash_xml, args.password)
        generated_files["flash.xml"] = str(flash_xml)

        flash_info = validate_flash_xml(flash_xml, image_dir)

        scatter_x = find_existing_scatter_x(image_dir, flash_info.get("scatter"))
        if not scatter_x:
            raise ValidationError("No scatter .x file found in image directory")

        scatter_xml_name = scatter_x.name.replace(".x", ".xml")
        scatter_xml = output_dir / scatter_xml_name
        decrypted_sizes[scatter_xml_name] = decrypt_lenovo_x_file(scatter_x, scatter_xml, args.password)
        generated_files[scatter_xml_name] = str(scatter_xml)

        scatter_info = validate_scatter(scatter_xml, image_dir)

        extra_candidates = [image_dir / "flash_efuse.x", *sorted(image_dir.glob("*scatter*_efuse.x"))]
        for extra_source in extra_candidates:
            if extra_source.exists():
                extra_dest = output_dir / extra_source.name.replace(".x", ".xml")
                decrypted_sizes[extra_dest.name] = decrypt_lenovo_x_file(extra_source, extra_dest, args.password)
                generated_files[extra_dest.name] = str(extra_dest)
                parse_xml(extra_dest)

        copied_files = copy_support_files(image_dir, output_dir, flash_info)
        partition_exports = write_partition_exports(output_dir, scatter_info["partition_rows"])
        stage_info = create_staging_folder(
            image_dir=image_dir,
            output_dir=output_dir,
            generated_files=generated_files,
            copied_files=copied_files,
            referenced_files=scatter_info["referenced_files"],
            extra_files=partition_exports,
        )

        report = build_report(
            package_dir=package_dir,
            image_dir=image_dir,
            output_dir=output_dir,
            flash_info=flash_info,
            scatter_info=scatter_info,
            decrypted_sizes=decrypted_sizes,
            copied_files=copied_files,
            extra_outputs=generated_files,
            partition_exports=partition_exports,
            stage_info=stage_info,
        )

        report_path = output_dir / "validation_report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

        print("Decryption and validation completed successfully.")
        print(f"Output directory: {output_dir}")
        print(f"Validation report: {report_path}")
        print(json.dumps(report["scatter_summary"], indent=2))
        return 0
    except ValidationError as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
