#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK Matrix FastAPI Backend
FastAPI приложение для загрузки, кэширования и предоставления MITRE матрицы
"""

import json
import asyncio
import aiohttp
import logging
from datetime import datetime
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from pathlib import Path

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Инициализация FastAPI
app = FastAPI(
    title="MITRE ATT&CK Matrix API",
    description="API для работы с матрицей MITRE ATT&CK",
    version="1.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Константы
GITHUB_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CACHE_DIR = Path("./cache")
CACHE_FILE = CACHE_DIR / "mitre_matrix.json"
CACHE_METADATA = CACHE_DIR / "metadata.json"

# Интервалы обновления (в секундах)
UPDATE_INTERVALS = {
    "1_hour": 3600,
    "6_hours": 21600,
    "12_hours": 43200,
    "24_hours": 86400,
    "7_days": 604800,
}


class AppState:
    """Глобальное состояние приложения"""

    matrix_data: Optional[Dict] = None
    last_update: Optional[datetime] = None
    update_interval: int = UPDATE_INTERVALS["24_hours"]
    is_updating: bool = False
    update_count: int = 0


app.state.state = AppState()

# Создание директории кэша
CACHE_DIR.mkdir(exist_ok=True)


# Модели Pydantic
class UpdateIntervalRequest(BaseModel):
    interval: str


class MatrixStats(BaseModel):
    total_tactics: int
    total_techniques: int
    total_subtechniques: int
    last_update: Optional[str]
    update_interval: str
    is_updating: bool


class Technique(BaseModel):
    id: str
    name: str
    platforms: List[str]


class TacticData(BaseModel):
    name: str
    techniques: List[Technique]


async def download_matrix() -> Optional[Dict]:
    """Загружает матрицу с GitHub, безопасно обрабатывая text/plain"""

    try:
        logger.info("📥 Загружаю матрицу MITRE с GitHub...")

        async with aiohttp.ClientSession() as session:
            async with session.get(GITHUB_URL, timeout=aiohttp.ClientTimeout(total=60)) as response:
                if response.status != 200:
                    logger.error(f"❌ Ошибка загрузки: статус {response.status}")
                    return None

                # GitHub raw может отдать text/plain; читаем как текст и парсим вручную
                text = await response.text()
                try:
                    data = json.loads(text)
                except json.JSONDecodeError as e:
                    logger.error(f"❌ Ошибка JSON-декодинга: {e}")
                    return None

                logger.info("✅ Матрица успешно загружена")
                return data

    except Exception as e:
        logger.error(f"❌ Ошибка при загрузке: {e}")
        return None


def parse_matrix(raw_data: Dict) -> Optional[Dict]:
    """Парсит матрицу из сырых данных"""

    try:
        techniques: Dict[str, Dict] = {}
        subtechniques: Dict[str, Dict] = {}
        tactics: Dict[str, Dict] = {}
        matrix: Dict[str, List[Dict]] = {}

        objects = raw_data.get("objects", [])

        # Первый проход: собираем объекты
        for obj in objects:
            obj_type = obj.get("type", "")

            if obj_type == "x-mitre-tactic":
                tactic_name = obj.get("name", "Unknown").lower()
                tactics[tactic_name] = {
                    "name": obj.get("name", "Unknown"),
                    "description": obj.get("description", ""),
                    "shortname": obj.get("x_mitre_shortname", ""),
                }
                matrix[tactic_name] = []

            elif obj_type == "attack-pattern":
                is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
                kill_chain = obj.get("kill_chain_phases", [])
                tactic_names = [kc.get("phase_name", "").lower() for kc in kill_chain]

                external_refs = obj.get("external_references", [])
                external_id = "N/A"
                if external_refs:
                    # Берём первый external_id, если он есть
                    external_id = external_refs[0].get("external_id", "N/A")

                tech_data = {
                    "id": external_id,
                    "name": obj.get("name", "Unknown"),
                    "description": obj.get("description", "")[:300],
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": tactic_names,
                }

                if is_subtechnique:
                    subtechniques[obj.get("id")] = tech_data
                else:
                    techniques[obj.get("id")] = tech_data

        # Второй проход: строим матрицу
        for tech_id, technique in techniques.items():
            for tactic in technique["tactics"]:
                if tactic in matrix:
                    matrix[tactic].append(
                        {
                            "id": technique["id"],
                            "name": technique["name"],
                            "platforms": technique["platforms"],
                        }
                    )

        # Связываем подтехники
        for subtech_id, subtech in subtechniques.items():
            for tech_id, technique in techniques.items():
                if subtech["id"].startswith(technique["id"]):
                    technique.setdefault("subtechniques", []).append(subtech)

        return {
            "tactics": tactics,
            "matrix": matrix,
            "statistics": {
                "total_tactics": len(tactics),
                "total_techniques": len(techniques),
                "total_subtechniques": len(subtechniques),
            },
        }

    except Exception as e:
        logger.error(f"❌ Ошибка при парсинге: {e}")
        return None


def save_to_cache(data: Dict) -> None:
    """Сохраняет данные в кэш"""

    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        metadata = {
            "last_update": datetime.now().isoformat(),
            "update_interval": app.state.state.update_interval,
        }
        with open(CACHE_METADATA, "w", encoding="utf-8") as f:
            json.dump(metadata, f)

        logger.info("✅ Данные сохранены в кэш")
    except Exception as e:
        logger.error(f"❌ Ошибка при сохранении кэша: {e}")


def load_from_cache() -> Optional[Dict]:
    """Загружает данные из кэша"""

    try:
        if CACHE_FILE.exists():
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                logger.info("📂 Загружаю данные из кэша")
                return json.load(f)
    except Exception as e:
        logger.error(f"❌ Ошибка при загрузке кэша: {e}")
    return None


async def update_matrix_task(_: BackgroundTasks) -> None:
    """Фоновая задача обновления матрицы"""

    while True:
        try:
            await asyncio.sleep(app.state.state.update_interval)

            if not app.state.state.is_updating:
                app.state.state.is_updating = True
                logger.info("🔄 Начинаю обновление матрицы...")

                raw_data = await download_matrix()
                if raw_data:
                    parsed_data = parse_matrix(raw_data)
                    if parsed_data:
                        app.state.state.matrix_data = parsed_data
                        app.state.state.last_update = datetime.now()
                        app.state.state.update_count += 1
                        save_to_cache(parsed_data)
                        logger.info(
                            "✅ Обновление #%s завершено",
                            app.state.state.update_count,
                        )

                app.state.state.is_updating = False
        except Exception as e:
            logger.error(f"❌ Ошибка в фоновой задаче: {e}")
            app.state.state.is_updating = False


@app.on_event("startup")
async def startup_event() -> None:
    """Инициализация при запуске приложения"""

    logger.info("🚀 Запуск приложения...")

    cached_data = load_from_cache()
    if cached_data:
        app.state.state.matrix_data = cached_data
        app.state.state.last_update = datetime.now()
        logger.info("✅ Матрица загружена из кэша")
    else:
        raw_data = await download_matrix()
        if raw_data:
            parsed_data = parse_matrix(raw_data)
            if parsed_data:
                app.state.state.matrix_data = parsed_data
                app.state.state.last_update = datetime.now()
                save_to_cache(parsed_data)

    asyncio.create_task(update_matrix_task(BackgroundTasks()))


@app.get("/")
async def root() -> HTMLResponse | Dict[str, str]:
    """Возвращает главную страницу"""

    html_path = Path("frontend/index.html")
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return {"message": "Frontend не найден"}


@app.get("/api/matrix", tags=["Matrix"])
async def get_matrix() -> Dict:
    """Получить полную матрицу"""

    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")
    return app.state.state.matrix_data


@app.get("/api/matrix/tactics", tags=["Matrix"])
async def get_tactics() -> Dict:
    """Получить список тактик"""

    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")
    return app.state.state.matrix_data.get("tactics", {})


@app.get("/api/matrix/tactic/{tactic}", tags=["Matrix"])
async def get_tactic(tactic: str) -> Dict:
    """Получить техники конкретной тактики"""

    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")

    tactic_lower = tactic.lower()
    matrix = app.state.state.matrix_data.get("matrix", {})

    if tactic_lower not in matrix:
        raise HTTPException(status_code=404, detail=f"Тактика '{tactic}' не найдена")

    return {"tactic": tactic, "techniques": matrix[tactic_lower]}


@app.get("/api/statistics", tags=["Statistics"])
async def get_statistics() -> MatrixStats:
    """Получить статистику"""

    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")

    stats = app.state.state.matrix_data.get("statistics", {})

    interval_str = next(
        (k for k, v in UPDATE_INTERVALS.items() if v == app.state.state.update_interval),
        "24_hours",
    )

    return MatrixStats(
        total_tactics=stats.get("total_tactics", 0),
        total_techniques=stats.get("total_techniques", 0),
        total_subtechniques=stats.get("total_subtechniques", 0),
        last_update=app.state.state.last_update.isoformat()
        if app.state.state.last_update
        else None,
        update_interval=interval_str,
        is_updating=app.state.state.is_updating,
    )


@app.post("/api/settings/update-interval", tags=["Settings"])
async def set_update_interval(request: UpdateIntervalRequest) -> Dict:
    """Изменить интервал обновления"""

    if request.interval not in UPDATE_INTERVALS:
        raise HTTPException(
            status_code=400,
            detail=f"Неизвестный интервал. Доступные: {list(UPDATE_INTERVALS.keys())}",
        )

    app.state.state.update_interval = UPDATE_INTERVALS[request.interval]
    logger.info("⚙️  Интервал обновления установлен: %s", request.interval)

    return {
        "message": "Интервал обновления изменен",
        "interval": request.interval,
        "seconds": app.state.state.update_interval,
    }


@app.post("/api/matrix/refresh", tags=["Matrix"])
async def refresh_matrix() -> Dict:
    """Принудительное обновление матрицы"""

    if app.state.state.is_updating:
        raise HTTPException(status_code=429, detail="Обновление уже в процессе")

    app.state.state.is_updating = True
    try:
        logger.info("🔄 Принудительное обновление матрицы...")
        raw_data = await download_matrix()
        if raw_data:
            parsed_data = parse_matrix(raw_data)
            if parsed_data:
                app.state.state.matrix_data = parsed_data
                app.state.state.last_update = datetime.now()
                app.state.state.update_count += 1
                save_to_cache(parsed_data)
                return {
                    "message": "Матрица успешно обновлена",
                    "update_count": app.state.state.update_count,
                    "last_update": app.state.state.last_update.isoformat(),
                }
        raise HTTPException(status_code=500, detail="Ошибка при загрузке матрицы")
    finally:
        app.state.state.is_updating = False


@app.get("/api/search", tags=["Search"])
async def search_techniques(q: str) -> Dict:
    """Поиск техник по названию или ID"""

    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")

    query = q.lower()
    results = []

    for tactic, techniques in app.state.state.matrix_data.get("matrix", {}).items():
        for technique in techniques:
            if query in technique["name"].lower() or query in technique["id"].lower():
                results.append({"tactic": tactic, "technique": technique})

    return {"query": q, "results": results[:20]}


try:
    app.mount("/static", StaticFiles(directory="frontend"), name="static")
except Exception as e:
    logger.warning(f"⚠️  Не удалось смонтировать статические файлы: {e}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
