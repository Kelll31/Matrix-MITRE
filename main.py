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
from contextlib import asynccontextmanager
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from pathlib import Path

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    # Индекс для быстрого поиска техник по ID
    technique_index: Dict[str, Dict] = {}


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
    update_count: int


class ExternalReference(BaseModel):
    source_name: str
    description: Optional[str] = None
    url: Optional[str] = None
    external_id: Optional[str] = None


class Technique(BaseModel):
    id: str
    name: str
    description: str
    platforms: List[str] = []
    tactics: List[str] = []
    mitre_url: Optional[str] = None
    detection: Optional[str] = None
    external_references: List[ExternalReference] = []
    kill_chain_phases: List[str] = []
    subtechniques: Optional[List["Technique"]] = None


class TacticData(BaseModel):
    name: str
    shortname: str
    description: str
    techniques: List[Technique]


async def download_matrix() -> Optional[Dict]:
    """Загружает матрицу с GitHub, безопасно обрабатывая text/plain"""

    try:
        logger.info("📥 Загружаю матрицу MITRE с GitHub...")

        async with aiohttp.ClientSession() as session:
            async with session.get(
                GITHUB_URL, timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status != 200:
                    logger.error(f"❌ Ошибка загрузки: статус {response.status}")
                    return None

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
    """Парсит матрицу из сырых данных с иерархией: Тактика -> Техника -> Подтехника

    Собираем расширенные данные:
    - ATT&CK ID (Txxxx/Txxxx.yy)
    - name, description
    - tactics (phase_name), platforms
    - detection, external_references
    - kill_chain_phases
    """

    try:
        techniques: Dict[str, Dict] = {}
        subtechniques: Dict[str, Dict] = {}
        tactics: Dict[str, Dict] = {}
        matrix: Dict[str, List[Dict]] = {}
        technique_index: Dict[str, Dict] = {}

        objects = raw_data.get("objects", [])

        # Первый проход: собираем тактики и сырые техники с расширенными данными
        for obj in objects:
            obj_type = obj.get("type", "")

            if obj_type == "x-mitre-tactic":
                tactic_name = obj.get("name", "Unknown").lower().replace(" ", "-")
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

                # Ищем именно ATT&CK ID (Txxxx/Txxxx.yy) и URL
                external_id = "N/A"
                mitre_url = None
                for ref in external_refs:
                    source_name = ref.get("source_name", "").lower()
                    if source_name in {"mitre-attack", "attack", "mitre"}:
                        external_id = ref.get("external_id", external_id)
                        mitre_url = ref.get("url", mitre_url)
                        break
                if external_id == "N/A" and external_refs:
                    # Фолбэк на первый, если профильный не нашли
                    first = external_refs[0]
                    external_id = first.get("external_id", "N/A")
                    mitre_url = first.get("url", mitre_url)

                # Собираем detection и другие данные
                detection = obj.get("x_mitre_detection") or "Нет данных о детекции"

                # Форматируем external_references для вывода
                formatted_refs = []
                for ref in external_refs:
                    formatted_refs.append({
                        "source_name": ref.get("source_name", ""),
                        "description": ref.get("description"),
                        "url": ref.get("url"),
                        "external_id": ref.get("external_id"),
                    })

                tech_data = {
                    "id": external_id,
                    "name": obj.get("name", "Unknown"),
                    "description": obj.get("description", "") or "Описание недоступно в STIX JSON.",
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": tactic_names,
                    "mitre_url": mitre_url,
                    "detection": detection,
                    "external_references": formatted_refs,
                    "kill_chain_phases": [kc.get("phase_name", "") for kc in kill_chain],
                    "stix_id": obj.get("id", ""),  # Добавляем STIX ID для отладки
                }

                # Если external_id не начинается с T, толку от него мало для матрицы
                if not external_id.startswith("T"):
                    continue

                if is_subtechnique:
                    subtechniques[obj.get("id")] = tech_data
                else:
                    techniques[obj.get("id")] = tech_data

        # Индексируем техники и подтехники по ID для быстрого поиска
        for tech_id, tech_data in techniques.items():
            technique_index[tech_data["id"].lower()] = tech_data

        for sub_id, sub_data in subtechniques.items():
            technique_index[sub_data["id"].lower()] = sub_data

        # Второй проход: строим матрицу с подтехниками
        for tech_obj_id, technique in techniques.items():
            technique_subtechniques = []
            for sub_obj_id, subtech in subtechniques.items():
                # Сравниваем ATT&CK ID подптехники и техники по префиксу (T1234.xx начинается с T1234)
                if subtech["id"].startswith(technique["id"] + "."):
                    technique_subtechniques.append(
                        {
                            "id": subtech["id"],
                            "name": subtech["name"],
                            "description": subtech["description"],
                            "platforms": subtech["platforms"],
                            "tactics": subtech["tactics"],
                            "mitre_url": subtech["mitre_url"],
                            "detection": subtech["detection"],
                            "external_references": subtech["external_references"],
                            "kill_chain_phases": subtech["kill_chain_phases"],
                        }
                    )

            technique_obj = {
                "id": technique["id"],
                "name": technique["name"],
                "description": technique["description"],
                "platforms": technique["platforms"],
                "tactics": technique["tactics"],
                "mitre_url": technique["mitre_url"],
                "detection": technique["detection"],
                "external_references": technique["external_references"],
                "kill_chain_phases": technique["kill_chain_phases"],
                "subtechniques": sorted(
                    technique_subtechniques, key=lambda x: x["id"]
                ),
            }

            for tactic in technique["tactics"]:
                if tactic in matrix:
                    matrix[tactic].append(technique_obj)

        # Сортируем техники внутри каждой тактики по ID
        for tactic_key in matrix:
            matrix[tactic_key].sort(key=lambda x: x["id"])

        # Подсчёт статистики
        total_subtechniques = sum(
            len(t["subtechniques"]) for t in sum(matrix.values(), [])
        )

        return {
            "tactics": tactics,
            "matrix": matrix,
            "technique_index": technique_index,  # Добавляем индекс в результат
            "statistics": {
                "total_tactics": len(tactics),
                "total_techniques": len(techniques),
                "total_subtechniques": total_subtechniques,
            },
        }

    except Exception as e:
        logger.error(f"❌ Ошибка при парсинге: {e}")
        import traceback
        traceback.print_exc()
        return None


def save_to_cache(data: Dict) -> None:
    """Сохраняет данные в кэш"""

    try:
        # Не сохраняем индекс в кэш, он будет пересчитан при загрузке
        cache_data = {k: v for k, v in data.items() if k != "technique_index"}

        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)

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


async def update_matrix_task() -> None:
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
                        app.state.state.technique_index = parsed_data.get("technique_index", {})
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Управление жизненным циклом приложения - НОВЫЙ СТИЛЬ"""

    app.state.state = AppState()
    logger.info("🚀 Запуск приложения...")

    cached_data = load_from_cache()
    if cached_data:
        # Пересчитываем индекс при загрузке из кэша
        app.state.state.matrix_data = cached_data
        app.state.state.last_update = datetime.now()
        # Пересчитываем индекс
        app.state.state.technique_index = {}
        for tactics_dict in cached_data.get("matrix", {}).values():
            for tech in tactics_dict:
                app.state.state.technique_index[tech["id"].lower()] = tech
                for sub in tech.get("subtechniques", []):
                    app.state.state.technique_index[sub["id"].lower()] = sub
        logger.info("✅ Матрица загружена из кэша")
    else:
        raw_data = await download_matrix()
        if raw_data:
            parsed_data = parse_matrix(raw_data)
            if parsed_data:
                app.state.state.matrix_data = parsed_data
                app.state.state.technique_index = parsed_data.get("technique_index", {})
                app.state.state.last_update = datetime.now()
                save_to_cache(parsed_data)

    asyncio.create_task(update_matrix_task())

    yield

    logger.info("🛑 Завершение работы приложения...")


app = FastAPI(
    title="MITRE ATT&CK Matrix API",
    description="API для работы с матрицей MITRE ATT&CK",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_model=None)
async def root():
    html_path = Path("frontend/index.html")
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return {"message": "Frontend не найден"}


@app.get("/api/matrix", tags=["Matrix"])
async def get_matrix() -> Dict:
    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")
    return app.state.state.matrix_data


@app.get("/api/matrix/tactics", tags=["Matrix"])
async def get_tactics() -> Dict:
    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")
    return app.state.state.matrix_data.get("tactics", {})


@app.get("/api/matrix/tactic/{tactic}", tags=["Matrix"])
async def get_tactic(tactic: str) -> Dict:
    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")

    tactic_lower = tactic.lower().replace(" ", "-")
    matrix = app.state.state.matrix_data.get("matrix", {})
    tactics = app.state.state.matrix_data.get("tactics", {})

    if tactic_lower not in matrix:
        raise HTTPException(status_code=404, detail=f"Тактика '{tactic}' не найдена")

    return {"tactic": tactics.get(tactic_lower, {}), "techniques": matrix[tactic_lower]}


@app.get("/api/matrix/technique/{technique_id}", tags=["Matrix"])
async def get_technique(technique_id: str) -> Dict:
    """
    Получить техничику по ID (T1234 или T1234.001, etc)
    Использует индекс для быстрого поиска
    """
    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")

    # Нормализуем ID для поиска
    search_id = technique_id.upper()

    # Ищем в индексе
    if search_id in app.state.state.technique_index:
        return app.state.state.technique_index[search_id]

    # Фолбэк: полный поиск (на случай если индекс не обновился)
    matrix = app.state.state.matrix_data.get("matrix", {})
    for _, techniques in matrix.items():
        for tech in techniques:
            if tech["id"].upper() == search_id:
                return tech
            for sub in tech.get("subtechniques", []):
                if sub["id"].upper() == search_id:
                    return sub

    # Не нашли
    logger.warning(f"Техника '{technique_id}' не найдена. Индекс содержит {len(app.state.state.technique_index)} техник")
    raise HTTPException(status_code=404, detail=f"Техника '{technique_id}' не найдена")


@app.get("/api/statistics", tags=["Statistics"])
async def get_statistics() -> MatrixStats:
    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")

    stats = app.state.state.matrix_data.get("statistics", {})

    interval_str = next(
        (
            k
            for k, v in UPDATE_INTERVALS.items()
            if v == app.state.state.update_interval
        ),
        "24_hours",
    )

    return MatrixStats(
        total_tactics=stats.get("total_tactics", 0),
        total_techniques=stats.get("total_techniques", 0),
        total_subtechniques=stats.get("total_subtechniques", 0),
        last_update=(
            app.state.state.last_update.isoformat()
            if app.state.state.last_update
            else None
        ),
        update_interval=interval_str,
        is_updating=app.state.state.is_updating,
        update_count=app.state.state.update_count,
    )


@app.post("/api/settings/update-interval", tags=["Settings"])
async def set_update_interval(request: UpdateIntervalRequest) -> Dict:
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
                app.state.state.technique_index = parsed_data.get("technique_index", {})
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
async def search_techniques(q: str = Query(..., min_length=1), limit: int = Query(20, ge=1, le=100)) -> Dict:
    """
    Поиск техник по названию, ID, описанию или платформам.
    q: строка для поиска
    limit: максимум результатов (по умолчанию 20, макс 100)
    """
    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")

    query = q.lower()
    results = []

    for tactic, techniques in app.state.state.matrix_data.get("matrix", {}).items():
        for technique in techniques:
            # Ищем в разных полях
            match = (
                query in technique["name"].lower()
                or query in technique["id"].lower()
                or query in technique.get("description", "").lower()
                or any(query in platform.lower() for platform in technique.get("platforms", []))
            )

            if match:
                results.append({"tactic": tactic, "technique": technique})

            # Ищем также в подтехниках
            if len(results) < limit:
                for sub in technique.get("subtechniques", []):
                    sub_match = (
                        query in sub["name"].lower()
                        or query in sub["id"].lower()
                        or query in sub.get("description", "").lower()
                        or any(query in platform.lower() for platform in sub.get("platforms", []))
                    )
                    if sub_match:
                        results.append({"tactic": tactic, "technique": sub})

            if len(results) >= limit:
                break

        if len(results) >= limit:
            break

    return {"query": q, "count": len(results), "results": results[:limit]}


@app.get("/api/matrix/tactics/{tactic}/techniques", tags=["Matrix"])
async def get_tactic_techniques(
    tactic: str,
    platform: Optional[str] = Query(None),
    limit: int = Query(None),
) -> Dict:
    """
    Получить все техники тактики с опциональной фильтрацией по платформе
    """
    if not app.state.state.matrix_data:
        raise HTTPException(status_code=503, detail="Матрица еще не загружена")

    tactic_lower = tactic.lower().replace(" ", "-")
    matrix = app.state.state.matrix_data.get("matrix", {})

    if tactic_lower not in matrix:
        raise HTTPException(status_code=404, detail=f"Тактика '{tactic}' не найдена")

    techniques = matrix[tactic_lower]

    # Фильтруем по платформе если указана
    if platform:
        techniques = [t for t in techniques if platform.lower() in [p.lower() for p in t.get("platforms", [])]]

    if limit:
        techniques = techniques[:limit]

    return {"tactic": tactic_lower, "count": len(techniques), "techniques": techniques}


try:
    app.mount("/static", StaticFiles(directory="frontend"), name="static")
except Exception as e:
    logger.warning(f"⚠️  Не удалось смонтировать статические файлы: {e}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
