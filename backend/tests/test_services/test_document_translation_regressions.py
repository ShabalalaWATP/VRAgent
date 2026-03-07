"""Regression tests for document translation and reprocess edge cases."""

import asyncio
import io
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException, UploadFile
from starlette.datastructures import Headers

from backend import models
from backend.models.models import DocumentTranslation
from backend.routers import project_files
from backend.services.document_translation_service import document_translation_service


def test_normalize_translation_mapping_keeps_zero_id() -> None:
    mapping = document_translation_service._normalize_translation_mapping(
        [
            {"id": 0, "translation": "Hello"},
            {"id": 1, "translation": "World"},
        ]
    )

    assert mapping[0] == "Hello"
    assert mapping[1] == "World"


def _create_translation(
    db,
    project_id: int,
    mime_type: str,
    output_filename: str | None = None,
    filename: str = "input.txt",
    original_filename: str = "input.txt",
    file_path: str = "C:/tmp/input.txt",
) -> DocumentTranslation:
    translation = DocumentTranslation(
        project_id=project_id,
        filename=filename,
        original_filename=original_filename,
        file_path=file_path,
        file_size=8,
        mime_type=mime_type,
        target_language="English",
        status="completed",
        output_filename=output_filename,
    )
    db.add(translation)
    db.commit()
    db.refresh(translation)
    return translation


def test_reprocess_rejects_invalid_export_format(monkeypatch, db, sample_project) -> None:
    monkeypatch.setattr(project_files, "check_project_edit_access", lambda *_args, **_kwargs: None)
    translation = _create_translation(
        db=db,
        project_id=sample_project.id,
        mime_type="application/pdf",
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            project_files.reprocess_document_translation(
                project_id=sample_project.id,
                translation_id=translation.id,
                background_tasks=BackgroundTasks(),
                export_format="zip",
                db=db,
                current_user=SimpleNamespace(id=1),
            )
        )

    assert exc_info.value.status_code == 400
    assert "Invalid export format. Use 'pdf' or 'docx'." in exc_info.value.detail


def test_reprocess_rejects_non_pdf_source(monkeypatch, db, sample_project) -> None:
    monkeypatch.setattr(project_files, "check_project_edit_access", lambda *_args, **_kwargs: None)
    translation = _create_translation(
        db=db,
        project_id=sample_project.id,
        mime_type="text/plain",
        output_filename="old_output.docx",
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            project_files.reprocess_document_translation(
                project_id=sample_project.id,
                translation_id=translation.id,
                background_tasks=BackgroundTasks(),
                export_format=None,
                db=db,
                current_user=SimpleNamespace(id=1),
            )
        )

    assert exc_info.value.status_code == 400
    assert "Only PDF source translations can be reprocessed." in exc_info.value.detail


def test_upload_rejects_non_pdf_source(monkeypatch, db, sample_project, tmp_path) -> None:
    monkeypatch.setattr(project_files, "check_project_edit_access", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(project_files, "get_upload_dir", lambda: tmp_path)

    upload = UploadFile(filename="input.txt", file=io.BytesIO(b"hello"))
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            project_files.upload_document_for_translation(
                project_id=sample_project.id,
                background_tasks=BackgroundTasks(),
                file=upload,
                target_language="English",
                source_language=None,
                ocr_languages=None,
                translate_images=False,
                export_format="pdf",
                db=db,
                current_user=SimpleNamespace(id=1, username="tester"),
            )
        )

    assert exc_info.value.status_code == 400
    assert "Only PDF files are supported for document translation." in exc_info.value.detail


def test_upload_rejects_image_translation_without_ocr(monkeypatch, db, sample_project, tmp_path) -> None:
    monkeypatch.setattr(project_files, "check_project_edit_access", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(project_files, "get_upload_dir", lambda: tmp_path)
    monkeypatch.setattr(document_translation_service, "is_ocr_available", lambda: False)

    upload = UploadFile(filename="input.pdf", file=io.BytesIO(b"%PDF-1.4 fake"))
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            project_files.upload_document_for_translation(
                project_id=sample_project.id,
                background_tasks=BackgroundTasks(),
                file=upload,
                target_language="English",
                source_language=None,
                ocr_languages=None,
                translate_images=True,
                export_format="pdf",
                db=db,
                current_user=SimpleNamespace(id=1, username="tester"),
            )
        )

    assert exc_info.value.status_code == 400
    assert "requires OCR" in exc_info.value.detail


def test_upload_accepts_pdf_with_generic_mime(monkeypatch, db, sample_project, tmp_path) -> None:
    monkeypatch.setattr(project_files, "check_project_edit_access", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(project_files, "get_upload_dir", lambda: tmp_path)
    upload = UploadFile(
        filename="scan.pdf",
        file=io.BytesIO(b"%PDF-1.4 fake"),
        headers=Headers({"content-type": "application/octet-stream"}),
    )

    result = asyncio.run(
        project_files.upload_document_for_translation(
            project_id=sample_project.id,
            background_tasks=BackgroundTasks(),
            file=upload,
            target_language="English",
            source_language=None,
            ocr_languages=None,
            translate_images=False,
            export_format="pdf",
            db=db,
            current_user=SimpleNamespace(id=1, username="tester"),
        )
    )

    assert result.mime_type == "application/pdf"
    assert result.original_filename == "scan.pdf"


def test_reprocess_rejects_image_translation_without_ocr(monkeypatch, db, sample_project) -> None:
    monkeypatch.setattr(project_files, "check_project_edit_access", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(document_translation_service, "is_ocr_available", lambda: False)
    translation = _create_translation(
        db=db,
        project_id=sample_project.id,
        mime_type="application/pdf",
        output_filename="old_output.pdf",
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            project_files.reprocess_document_translation(
                project_id=sample_project.id,
                translation_id=translation.id,
                background_tasks=BackgroundTasks(),
                export_format="pdf",
                translate_images=True,
                db=db,
                current_user=SimpleNamespace(id=1),
            )
        )

    assert exc_info.value.status_code == 400
    assert "requires OCR" in exc_info.value.detail


def test_reprocess_accepts_pdf_extension_with_generic_mime(monkeypatch, db, sample_project) -> None:
    monkeypatch.setattr(project_files, "check_project_edit_access", lambda *_args, **_kwargs: None)
    translation = _create_translation(
        db=db,
        project_id=sample_project.id,
        mime_type="application/octet-stream",
        output_filename="old_output.pdf",
        filename="legacy.pdf",
        original_filename="legacy.pdf",
        file_path="C:/tmp/legacy.pdf",
    )

    result = asyncio.run(
        project_files.reprocess_document_translation(
            project_id=sample_project.id,
            translation_id=translation.id,
            background_tasks=BackgroundTasks(),
            export_format="pdf",
            db=db,
            current_user=SimpleNamespace(id=1),
        )
    )

    db.refresh(translation)
    assert result["status"] == "reprocessing"
    assert translation.status == "pending"
    assert translation.mime_type == "application/pdf"
