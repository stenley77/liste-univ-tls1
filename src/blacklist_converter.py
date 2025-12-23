#!/usr/bin/env python3
"""
Convertisseur de listes noires UT-Capitole vers format AdGuardHome
Basé sur l'analyse du projet stenley77/liste-univ-tls1
"""

import asyncio
import aiohttp
import logging
import yaml
import re
import os
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin
import argparse
import io

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BlacklistConverter:
    def __init__(self, config_path: str = "src/config.yaml"):
        """Initialise le convertisseur avec la configuration"""
        self.config = self._load_config(config_path)
        self.session = None
        # URL corrigée basée sur l'analyse du projet existant
        self.base_url = self.config['source']['base_url']
        self.output_dir = Path(self.config['output']['directory'])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def _load_config(self, config_path: str) -> Dict:
        """Charge la configuration depuis le fichier YAML"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Fichier de configuration non trouvé: {config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Erreur de parsing YAML: {e}")
            raise

    async def __aenter__(self):
        """Context manager pour les sessions HTTP"""
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=300, connect=30)  # Timeout augmenté pour les archives
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'AdGuard-Blacklist-Converter/2.0'}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Fermeture de la session HTTP"""
        if self.session:
            await self.session.close()

    async def download_and_extract_archive(self, category_name: str) -> Set[str]:
        """Télécharge et extrait une archive tar.gz depuis FTP UT-Capitole"""
        archive_url = f"{self.base_url}{category_name}.tar.gz"
        logger.info(f"📥 Téléchargement de {archive_url}")
        
        try:
            async with self.session.get(archive_url) as response:
                if response.status != 200:
                    logger.warning(f"❌ Erreur HTTP {response.status} pour {archive_url}")
                    return set()
                
                # Téléchargement de l'archive
                archive_data = await response.read()
                logger.info(f"✅ Archive téléchargée: {len(archive_data)} bytes")
                
                # Extraction et traitement
                return await self._extract_and_process_archive(archive_data, category_name)
                
        except asyncio.TimeoutError:
            logger.error(f"⏱️ Timeout lors du téléchargement de {archive_url}")
            return set()
        except Exception as e:
            logger.error(f"❌ Erreur lors du téléchargement de {archive_url}: {e}")
            return set()

    async def _extract_and_process_archive(self, archive_data: bytes, category_name: str) -> Set[str]:
        """Extrait et traite le contenu d'une archive tar.gz"""
        domains = set()
        
        try:
            # Extraction de l'archive en mémoire
            with tarfile.open(fileobj=io.BytesIO(archive_data), mode='r:gz') as tar:
                # Recherche du fichier 'domains'
                domains_file = None
                for member in tar.getmembers():
                    if member.name.endswith('/domains') or member.name == 'domains':
                        domains_file = member
                        break
                
                if not domains_file:
                    logger.warning(f"❌ Fichier 'domains' non trouvé dans l'archive {category_name}")
                    return set()
                
                # Extraction du contenu du fichier domains
                extracted_file = tar.extractfile(domains_file)
                if extracted_file:
                    content = extracted_file.read().decode('utf-8', errors='ignore')
                    total_lines = len(content.split('\n'))
                    logger.info(f"📄 Fichier domains: {total_lines} lignes totales")
                    
                    # Traitement optimisé inspiré du script bash
                    domains = await self._fast_process_domains(content)
                    
        except tarfile.TarError as e:
            logger.error(f"❌ Erreur d'extraction de l'archive {category_name}: {e}")
        except Exception as e:
            logger.error(f"❌ Erreur de traitement de l'archive {category_name}: {e}")
            
        return domains

    async def _fast_process_domains(self, content: str) -> Set[str]:
        """Traitement rapide des domaines inspiré du pipeline bash optimisé"""
        domains = set()
        
        for line in content.split('\n'):
            # Nettoyage de base (équivalent sed + tr)
            line = re.sub(r'#.*', '', line)  # Supprime commentaires
            line = line.strip().lower()  # Trim et lowercase
            line = line.replace('\r', '')  # Supprime \r
            
            if not line:  # Ignore lignes vides
                continue
                
            # Ignore les adresses IP
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
                continue
                
            # Ignore les caractères spéciaux problématiques
            if re.search(r'[\*\(\)\[\]{}\\$?|]|https?://|//', line):
                continue
                
            # Nettoie les ports et wildcards
            line = re.sub(r':\d+$', '', line)  # Supprime ports
            line = re.sub(r'/.*$', '', line)   # Supprime chemins
            line = re.sub(r'^[\|\*]+', '', line)  # Supprime préfixes
            line = re.sub(r'[\^\*]+$', '', line)  # Supprime suffixes
            
            # Doit contenir un point et être valide
            if not '.' in line:
                continue
                
            # Validation basique
            if not re.match(r'^[a-z0-9.-]+$', line):
                continue
                
            # Évite les doubles points
            if '..' in line:
                continue
                
            # Longueur raisonnable
            if len(line) < 4 or len(line) > 253:
                continue
                
            # Validation TLD (au moins 2 chars pour TLD et SLD)
            parts = line.split('.')
            if len(parts) < 2 or len(parts[-1]) < 2 or len(parts[-2]) < 2:
                continue
                
            domains.add(line)
            
        return domains

    def _aggregate_subdomains(self, domains: Set[str]) -> Set[str]:
        """Agrégation des sous-domaines (équivalent du script awk)"""
        logger.info("🔄 Agrégation des sous-domaines...")
        
        # Convertir en liste triée pour traitement
        sorted_domains = sorted(domains)
        domain_tree = {}
        
        # Construction de l'arbre des domaines
        for domain in sorted_domains:
            parts = domain.split('.')
            # Générer tous les domaines parents possibles
            for i in range(len(parts)):
                parent = '.'.join(parts[i:])
                if parent not in domain_tree:
                    domain_tree[parent] = set()
                domain_tree[parent].add(domain)
        
        # Filtrage - garder seulement les domaines qui n'ont pas de parent dans la liste
        final_domains = set()
        for domain in sorted_domains:
            parts = domain.split('.')
            has_parent = False
            
            # Vérifier si un domaine parent existe dans notre liste
            for i in range(1, len(parts)):
                parent = '.'.join(parts[i:])
                if parent in domains and parent != domain:
                    has_parent = True
                    break
                    
            if not has_parent:
                final_domains.add(domain)
        
        reduction_percent = (1 - len(final_domains) / len(domains)) * 100 if domains else 0
        logger.info(f"📊 Réduction: {reduction_percent:.1f}% ({len(domains)} → {len(final_domains)})")
        
        return final_domains

    def _convert_to_adguard_format(self, domains: Set[str]) -> List[str]:
        """Convertit les domaines au format AdGuardHome"""
        # Agrégation des sous-domaines avant conversion
        aggregated_domains = self._aggregate_subdomains(domains)
        
        # Conversion au format AdGuard
        adguard_rules = []
        for domain in sorted(aggregated_domains):
            adguard_rules.append(f"||{domain}^")
            
        return adguard_rules

    async def process_category(self, category_config: Dict) -> Tuple[str, int]:
        """Traite une catégorie de listes noires"""
        category_name = category_config['name']
        start_time = datetime.now()
        
        logger.info(f"=" * 50)
        logger.info(f"Processing {category_name}...")
        logger.info(f"=" * 50)
        
        # Téléchargement et extraction
        domains = await self.download_and_extract_archive(category_name)
        
        if not domains:
            logger.warning(f"❌ Aucun domaine trouvé pour {category_name}")
            return category_name, 0

        logger.info(f"📥 Domaines extraits: {len(domains)}")

        # Conversion au format AdGuard avec agrégation
        adguard_rules = self._convert_to_adguard_format(domains)
        
        # Sauvegarde
        output_path = await self._save_adguard_list(category_config, adguard_rules)
        
        # Statistiques finales
        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(f"📤 Fichier final: {len(adguard_rules)} règles")
        logger.info(f"⏱️ Temps de traitement: {elapsed:.1f}s")
        
        # Aperçu du contenu
        if adguard_rules:
            logger.info("📋 Premiers 5 éléments:")
            for rule in adguard_rules[:5]:
                logger.info(f"  {rule}")
            logger.info("📋 Derniers 5 éléments:")
            for rule in adguard_rules[-5:]:
                logger.info(f"  {rule}")
        
        logger.info(f"✅ {category_name} terminé")
        logger.info("")
        
        return category_name, len(adguard_rules)

    async def _save_adguard_list(self, category_config: Dict, rules: List[str]) -> Path:
        """Sauvegarde la liste AdGuard avec gestion des gros fichiers"""
        output_filename = category_config.get('output_filename', 
                                            f"adguardhome_{category_config['name']}")
        output_path = self.output_dir / category_config['name']
        output_path.mkdir(exist_ok=True)
        
        final_path = output_path / output_filename
        
        # Génération du contenu
        header = self._generate_header(category_config, len(rules))
        content = header + '\n' + '\n'.join(rules) + '\n'
        
        # Vérification de la taille (limite GitHub: 100MB)
        max_size = self.config.get('output', {}).get('max_file_size', 104857600)  # 100MB
        content_size = len(content.encode('utf-8'))
        
        if content_size > max_size:
            logger.warning(f"📦 Fichier {final_path} dépasse {max_size//1048576}MB, division en parties...")
            await self._split_large_file(final_path, content, max_size // 2)
        else:
            with open(final_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"✅ Fichier sauvegardé: {final_path} ({content_size//1024}KB)")
            
        return final_path

    async def _split_large_file(self, base_path: Path, content: str, split_size: int):
        """Divise un gros fichier en plusieurs parties"""
        lines = content.split('\n')
        header_lines = [line for line in lines if line.startswith('!')]
        rule_lines = [line for line in lines if line and not line.startswith('!')]
        
        part = 0
        current_size = 0
        current_lines = header_lines.copy()
        
        for rule in rule_lines:
            rule_size = len(rule.encode('utf-8')) + 1  # +1 pour \n
            
            if current_size + rule_size > split_size and len(current_lines) > len(header_lines):
                # Sauvegarde de la partie actuelle
                part_path = base_path.parent / f"{base_path.name}_part{part:02d}"
                with open(part_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(current_lines) + '\n')
                logger.info(f"✅ Partie {part} sauvegardée: {part_path} ({current_size//1024}KB)")
                
                # Nouvelle partie
                part += 1
                current_lines = header_lines.copy()
                current_size = sum(len(line.encode('utf-8')) + 1 for line in header_lines)
            
            current_lines.append(rule)
            current_size += rule_size
        
        # Dernière partie
        if len(current_lines) > len(header_lines):
            part_path = base_path.parent / f"{base_path.name}_part{part:02d}"
            with open(part_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(current_lines) + '\n')
            logger.info(f"✅ Partie {part} sauvegardée: {part_path} ({current_size//1024}KB)")

    def _generate_header(self, category_config: Dict, rule_count: int) -> str:
        """Génère l'en-tête du fichier AdGuard"""
        now = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
        
        header = f"""! Title: {category_config.get('title', category_config['name'])} - AdGuard
! Description: {category_config.get('description', 'Liste noire convertie depuis UT-Capitole')}
! Homepage: https://github.com/your-repo/adguard-blacklists
! Source: {self.base_url}{category_config['name']}.tar.gz
! Rules count: {rule_count}
! Updated: {now}
! Expires: 7 days
!"""
        return header

    async def run(self) -> Dict[str, int]:
        """Exécute la conversion complète"""
        logger.info("🚀 Début de la conversion des listes noires UT-Capitole")
        logger.info(f"Source: {self.base_url}")
        logger.info(f"Destination: {self.output_dir}")
        logger.info("")
        
        results = {}
        
        # Traite chaque catégorie
        for category_config in self.config['categories']:
            category_name, rule_count = await self.process_category(category_config)
            results[category_name] = rule_count
        
        # Résumé final
        logger.info("📊 RÉSUMÉ FINAL:")
        total_rules = 0
        for category, count in results.items():
            logger.info(f"  {category}: {count:,} règles")
            total_rules += count
        logger.info(f"  TOTAL: {total_rules:,} règles")
        
        logger.info("🎉 Conversion terminée avec succès")
        return results

async def main():
    """Point d'entrée principal"""
    parser = argparse.ArgumentParser(description='Convertit les listes noires UT-Capitole pour AdGuardHome')
    parser.add_argument('--config', default='src/config.yaml', help='Chemin vers le fichier de configuration')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    parser.add_argument('--category', help='Traiter uniquement une catégorie spécifique')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        async with BlacklistConverter(args.config) as converter:
            if args.category:
                # Filtrer pour une seule catégorie
                original_categories = converter.config['categories']
                converter.config['categories'] = [
                    cat for cat in original_categories 
                    if cat['name'] == args.category
                ]
                if not converter.config['categories']:
                    logger.error(f"Catégorie '{args.category}' non trouvée")
                    return 1
            
            results = await converter.run()
            return 0 if any(results.values()) else 1
            
    except Exception as e:
        logger.error(f"❌ Erreur fatale: {e}")
        return 1

if __name__ == "__main__":
    exit(asyncio.run(main()))
