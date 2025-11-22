# server/app_with_ui.py
import os
import sys
import asyncio
from pathlib import Path

from fastapi.responses import RedirectResponse, FileResponse
from starlette.staticfiles import StaticFiles

# Windows: Selector 이벤트 루프
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

# UI 디렉토리 자동 탐색 (환경변수 > server/ui > server/static/ui)
UI_DIR = os.getenv("PG_UI_DIR")
if not UI_DIR:
    for p in (Path("server/ui"), Path("server/static/ui")):
        if p.exists():
            UI_DIR = str(p)
            break
if not UI_DIR:
    UI_DIR = "server/ui"

# 기존 API FastAPI 인스턴스
from server.app import app

# 정적 UI 서빙
app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")

# 루트 → /ui/
@app.get("/")
async def _root():
    return RedirectResponse("/ui/")

# favicon 처리
FAV = Path(UI_DIR) / "favicon.ico"
if FAV.exists():
    @app.get("/favicon.ico")
    async def favicon():
        return FileResponse(str(FAV))
else:
    @app.get("/favicon.ico")
    async def favicon_empty():
        return RedirectResponse("/ui/")
