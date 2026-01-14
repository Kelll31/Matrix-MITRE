#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITRE ATT&CK Matrix Parser - Ультимативный скрипт для парсинга матрицы MITRE
Красивая визуализация матрицы с техниками и подтехниками
"""

import json
import requests
import sys
from typing import Dict, List, Tuple
from collections import defaultdict
from urllib.parse import urljoin

# Установите кодировку UTF-8 для консоли (важно для Windows)
if sys.platform == 'win32':
    import os
    os.system('chcp 65001')

class MITREATTACKParser:
    """Парсер MITRE ATT&CK матрицы с красивой визуализацией"""
    
    # URL к официальному файлу MITRE
    GITHUB_RAW_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    
    # Цвета для консоли (ANSI)
    COLORS = {
        'HEADER': '\033[95m',
        'BLUE': '\033[94m',
        'CYAN': '\033[96m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'RED': '\033[91m',
        'ENDC': '\033[0m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m',
    }
    
    def __init__(self, url: str = None):
        """
        Инициализация парсера
        
        Args:
            url: URL к JSON файлу (если None, используется официальный GitHub URL)
        """
        self.url = url or self.GITHUB_RAW_URL
        self.data = None
        self.techniques = {}
        self.subtechniques = {}
        self.tactics = {}
        self.matrix = defaultdict(list)
        
    def download_data(self) -> bool:
        """
        Скачивает JSON данные с GitHub
        
        Returns:
            bool: True если успешно, False в противном случае
        """
        try:
            print(f"📥 Загружаю данные с GitHub...")
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(self.url, headers=headers, timeout=30)
            response.raise_for_status()
            
            self.data = response.json()
            print(f"✅ Данные успешно загружены! Размер: {len(response.text) / 1024 / 1024:.2f} МБ")
            return True
        except requests.RequestException as e:
            print(f"❌ Ошибка при загрузке: {e}")
            return False
    
    def parse_matrix(self) -> None:
        """Парсит матрицу из загруженных данных"""
        if not self.data or 'objects' not in self.data:
            print("❌ Невалидный формат данных!")
            return
        
        print("🔍 Парсирую матрицу...")
        
        objects = self.data['objects']
        
        # Первый проход: собираем все объекты
        for obj in objects:
            obj_type = obj.get('type', '')
            
            # Парсим Tactics (Тактики)
            if obj_type == 'x-mitre-tactic':
                tactic_id = obj.get('id', '')
                tactic_name = obj.get('name', 'Unknown')
                self.tactics[tactic_id] = {
                    'name': tactic_name,
                    'description': obj.get('description', ''),
                    'x_mitre_shortname': obj.get('x_mitre_shortname', '')
                }
            
            # Парсим Attack Patterns (Техники и подтехники)
            elif obj_type == 'attack-pattern':
                technique_id = obj.get('id', '')
                technique_name = obj.get('name', 'Unknown')
                is_subtechnique = obj.get('x_mitre_is_subtechnique', False)
                
                # Получаем тактики для этой техники
                kill_chain = obj.get('kill_chain_phases', [])
                tactic_names = [kc.get('phase_name', '') for kc in kill_chain]
                
                tech_data = {
                    'name': technique_name,
                    'description': obj.get('description', '')[:200],
                    'external_id': obj.get('external_references', [{}])[0].get('external_id', 'N/A'),
                    'tactics': tactic_names,
                    'platforms': obj.get('x_mitre_platforms', []),
                    'is_subtechnique': is_subtechnique
                }
                
                if is_subtechnique:
                    self.subtechniques[technique_id] = tech_data
                else:
                    self.techniques[technique_id] = tech_data
        
        # Второй проход: строим матрицу (только основные техники)
        for technique_id, technique in self.techniques.items():
            for tactic in technique['tactics']:
                self.matrix[tactic.lower()].append(technique)
        
        # Сортируем техники в каждой тактике
        for tactic in self.matrix:
            self.matrix[tactic].sort(key=lambda x: x['external_id'])
        
        # Связываем подтехники с техниками
        for subtechnique_id, subtechnique in self.subtechniques.items():
            for technique in self.techniques.values():
                if subtechnique['external_id'].startswith(technique['external_id']):
                    if 'subtechniques' not in technique:
                        technique['subtechniques'] = []
                    technique['subtechniques'].append(subtechnique)
        
        print(f"✅ Парсинг завершен!")
        print(f"   • Найдено тактик: {len(self.tactics)}")
        print(f"   • Найдено техник: {len(self.techniques)}")
        print(f"   • Найдено подтехник: {len(self.subtechniques)}")
    
    def colorize(self, text: str, color: str) -> str:
        """Добавляет цвет к тексту"""
        if sys.platform == 'win32':
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['ENDC']}"
    
    def print_beautiful_matrix(self) -> None:
        """Выводит красивую матрицу MITRE с техниками и подтехниками"""
        print("\n" + "="*120)
        print(self.colorize("🔥 ПОЛНАЯ МАТРИЦА MITRE ATT&CK С ТЕХНИКАМИ И ПОДТЕХНИКАМИ", 'BOLD'))
        print("="*120 + "\n")
        
        tactic_list = sorted(self.matrix.keys())
        
        for tactic_idx, tactic in enumerate(tactic_list, 1):
            techniques = self.matrix[tactic]
            
            # Заголовок тактики
            print(self.colorize(f"{'█' * 120}", 'CYAN'))
            print(self.colorize(f"  #{tactic_idx:2} ТАКТИКА: {tactic.upper()}", 'BOLD'))
            print(self.colorize(f"{'█' * 120}", 'CYAN'))
            print(f"  Всего техник: {len(techniques)}\n")
            
            for tech_idx, technique in enumerate(techniques, 1):
                tech_id = technique['external_id']
                tech_name = technique['name']
                platforms = ", ".join(technique['platforms']) if technique['platforms'] else "N/A"
                
                # Основная техника
                print(self.colorize(f"  ┌─ 【{tech_id}】 {tech_name}", 'YELLOW'))
                print(f"  │   📱 Платформы: {platforms}")
                
                # Подтехники если есть
                if 'subtechniques' in technique and technique['subtechniques']:
                    subtechniques = sorted(technique['subtechniques'], 
                                         key=lambda x: x['external_id'])
                    
                    for sub_idx, subtechnique in enumerate(subtechniques):
                        sub_id = subtechnique['external_id']
                        sub_name = subtechnique['name']
                        sub_platforms = ", ".join(subtechnique['platforms']) if subtechnique['platforms'] else "N/A"
                        
                        is_last = (sub_idx == len(subtechniques) - 1)
                        connector = "└─" if is_last else "├─"
                        continuation = "   " if is_last else "│  "
                        
                        print(self.colorize(f"  │{continuation}{connector} 【{sub_id}】 {sub_name}", 'GREEN'))
                        print(f"  │{continuation}   📱 {sub_platforms}")
                else:
                    print(f"  │   └─ (подтехник нет)")
                
                print(f"  │\n")
            
            print()
    
    def print_tactic_heatmap(self) -> None:
        """Выводит тепловую карту матрицы"""
        print("\n" + "="*120)
        print(self.colorize("🗺️  ТЕПЛОВАЯ КАРТА МАТРИЦЫ (количество техник по тактикам)", 'BOLD'))
        print("="*120 + "\n")
        
        # Находим максимум для нормализации
        max_techniques = max(len(techniques) for techniques in self.matrix.values())
        
        tactics_sorted = sorted(self.matrix.keys())
        
        # Выводим в несколько рядов для красоты
        for i in range(0, len(tactics_sorted), 4):
            batch = tactics_sorted[i:i+4]
            
            # Выводим названия
            for tactic in batch:
                print(f"{tactic.upper():25}", end="")
            print("\n", end="")
            
            # Выводим количество и полосочки
            for tactic in batch:
                count = len(self.matrix[tactic])
                bar_length = int((count / max_techniques) * 30) if max_techniques > 0 else 0
                bar = "█" * bar_length + "░" * (30 - bar_length)
                print(f"{bar} ({count:3})", end="")
            print("\n" + "-"*120 + "\n")
    
    def print_platform_matrix(self) -> None:
        """Выводит матрицу по платформам"""
        print("\n" + "="*120)
        print(self.colorize("🖥️  МАТРИЦА ПО ПЛАТФОРМАМ", 'BOLD'))
        print("="*120 + "\n")
        
        all_platforms = defaultdict(set)
        
        # Собираем все платформы и их техники
        for tactic, techniques in self.matrix.items():
            for technique in techniques:
                for platform in technique['platforms']:
                    all_platforms[platform].add(f"{technique['external_id']} - {technique['name']}")
        
        # Выводим отсортированные по количеству техник
        for platform in sorted(all_platforms.keys(), key=lambda x: len(all_platforms[x]), reverse=True):
            techniques = sorted(list(all_platforms[platform]))
            count = len(techniques)
            
            print(self.colorize(f"▶ {platform} ({count} техник)", 'BLUE'))
            
            for i, tech in enumerate(techniques[:5], 1):
                print(f"  {i}. {tech}")
            
            if count > 5:
                print(f"  ... и ещё {count - 5} техник")
            
            print()
    
    def print_statistics(self) -> None:
        """Выводит детальную статистику"""
        print("\n" + "="*120)
        print(self.colorize("📈 ДЕТАЛЬНАЯ СТАТИСТИКА", 'BOLD'))
        print("="*120 + "\n")
        
        all_platforms = defaultdict(int)
        technique_count_by_tactic = {}
        
        for tactic, techniques in self.matrix.items():
            technique_count_by_tactic[tactic] = len(techniques)
            for technique in techniques:
                for platform in technique['platforms']:
                    all_platforms[platform] += 1
        
        # Статистика по тактикам
        print(self.colorize("📊 Техники по тактикам:", 'YELLOW'))
        for tactic in sorted(technique_count_by_tactic.keys()):
            count = technique_count_by_tactic[tactic]
            bar = "█" * (count // 3)
            print(f"  {tactic:25} | {count:3} техник | {bar}")
        
        # Статистика по платформам
        print(f"\n\n{self.colorize('🖥️  Техники по платформам:', 'YELLOW')}")
        for platform in sorted(all_platforms.keys(), key=lambda x: all_platforms[x], reverse=True):
            count = all_platforms[platform]
            bar = "█" * (count // 10)
            print(f"  {platform:25} | {count:3} техник | {bar}")
        
        # Общая статистика
        total_techniques = len(self.techniques)
        total_subtechniques = len(self.subtechniques)
        total_tactics = len(self.matrix)
        
        print(f"\n\n{self.colorize('🎯 Общая статистика:', 'GREEN')}")
        print(f"  Всего тактик:        {total_tactics}")
        print(f"  Всего техник:        {total_techniques}")
        print(f"  Всего подтехник:     {total_subtechniques}")
        print(f"  Всего платформ:      {len(all_platforms)}")
    
    def export_to_json(self, filename: str = "mitre_matrix_parsed.json") -> None:
        """Экспортирует матрицу в JSON файл"""
        output = {
            'matrix': {},
            'statistics': {
                'total_tactics': len(self.matrix),
                'total_techniques': len(self.techniques),
                'total_subtechniques': len(self.subtechniques)
            }
        }
        
        # Строим матрицу для экспорта
        for tactic in self.matrix:
            output['matrix'][tactic] = []
            for tech in self.matrix[tactic]:
                tech_entry = {
                    'id': tech['external_id'],
                    'name': tech['name'],
                    'platforms': tech['platforms'],
                    'subtechniques': []
                }
                
                if 'subtechniques' in tech:
                    for subtech in tech['subtechniques']:
                        tech_entry['subtechniques'].append({
                            'id': subtech['external_id'],
                            'name': subtech['name'],
                            'platforms': subtech['platforms']
                        })
                
                output['matrix'][tactic].append(tech_entry)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, ensure_ascii=False, indent=2)
        
        print(f"\n✅ Матрица экспортирована в {filename}")


def main():
    """Главная функция"""
    print("╔" + "═"*118 + "╗")
    print("║" + " "*118 + "║")
    print("║" + "MITRE ATT&CK MATRIX PARSER - Красивая визуализация матрицы MITRE v3.0".center(118) + "║")
    print("║" + "January 2026".center(118) + "║")
    print("║" + " "*118 + "║")
    print("╚" + "═"*118 + "╝\n")
    
    parser = MITREATTACKParser()
    
    # Загружаем данные
    if not parser.download_data():
        return
    
    # Парсим матрицу
    parser.parse_matrix()
    
    # Выводим красивую матрицу
    parser.print_beautiful_matrix()
    
    # Выводим статистику
    parser.print_statistics()
    
    # Выводим тепловую карту
    parser.print_tactic_heatmap()
    
    # Выводим матрицу по платформам
    parser.print_platform_matrix()
    
    # Экспорт
    parser.export_to_json()
    
    print("\n" + "="*120)
    print("✅ Парсинг и визуализация завершены успешно!")
    print("="*120 + "\n")


if __name__ == '__main__':
    main()