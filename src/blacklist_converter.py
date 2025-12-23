#!/usr/bin/env python3
"""
Convertisseur de listes noires UT-Capitole vers format AdGuardHome
Version simplifiée pour GitHub Actions
"""

import asyncio
import aiohttp
import yaml
import re
import os
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple
import io
import logging
import argparse

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BlacklistConverter:
    def __init__(self, config_path: str = "src/config.yaml"):
        """Initialise le convertisseur avec la configuration"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Fichier de configuration non trouvé: {config_path}")
            # Configuration par défaut
            self.config = {
                'source': {
                    'base_url': 'ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/'
                },
                'output': {
                    'directory': 'output/adguard',
                    'max_file_size': 104857600,
                    'generate_master': False
                },
                'categories': [
                    {
                        'name': 'adult',
                        'title': 'Adult Content - UT Capitole',
                        'description': 'Sites à contenu adulte bloqués par l\'Université Toulouse 1 Capitole',
                        'output_filename': 'adguardhome_adult'
                    },
                    {
                        'name': 'malware',
                        'title': 'Malware - UT Capitole', 
                        'description': 'Sites malveillants identifiés par l\'Université Toulouse 1 Capitole',
                        'output_filename': 'adguardhome_malware'
                    },
                    {
                        'name': 'mixed_adult',
                        'title': 'Mixed Adult Content - UT Capitole',
                        'description': 'Contenu mixte adulte de l\'Université Toulouse 1 Capitole',
                        'output_filename': 'adguardhome_mixed_adult'
                    },
                    {
                        'name': 'ddos',
                        'title': 'DDoS Sources - UT Capitole',
                        'description': 'Sources de DDoS identifiées par l\'Université Toulouse 1 Capitole',
                        'output_filename': 'adguardhome_ddos'
                    }
                ]
            }
        
        self.session = None
        self.base_url = self.config['source']['base_url']
        self.output_dir = Path(self.config['output']['directory'])
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self):
        """Context manager pour les sessions HTTP"""
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=300, connect=30)
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

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Valide un nom de domaine selon les critères stricts
        Évite les règles trop larges comme @@||r^
        """
        # Vérifications de base
        if not domain or len(domain) < 4 or len(domain) > 253:
            return False
            
        # Doit contenir au moins un point
        if '.' not in domain:
            return False
            
        # Ne doit pas contenir de caractères invalides
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
            
        # Ne doit pas avoir de points consécutifs
        if '..' in domain:
            return False
            
        # Vérifier les parties du domaine
        parts = domain.split('.')
        if len(parts) < 2:
            return False
            
        # Chaque partie doit être valide
        for part in parts:
            if not part:  # Partie vide
                return False
            if len(part) > 63:  # Trop long
                return False
            if part.startswith('-') or part.endswith('-'):  # Tiret en début/fin
                return False
            if not re.match(r'^[a-z0-9-]+$', part):  # Caractères invalides
                return False
        
        # La dernière partie (TLD) doit avoir au moins 2 caractères
        if len(parts[-1]) < 2:
            return False
            
        # L'avant-dernière partie doit avoir au moins 2 caractères
        if len(parts[-2]) < 2:
            return False
            
        # Éviter les domaines trop courts qui pourraient bloquer trop largement
        # Par exemple "r" dans "@@||r^" bloquerait tous les domaines contenant 'r'
        if len(parts[-2]) == 1 and len(parts) == 2:
            logger.warning(f"⚠️ Domaine potentiellement trop large ignoré: {domain}")
            return False
            
        return True

    async def download_and_extract_archive(self, category_name: str) -> Set[str]:
        """Télécharge et extrait une archive tar.gz depuis UT-Capitole"""
        archive_url = f"{self.base_url}{category_name}.tar.gz"
        logger.info(f"📥 Téléchargement de {archive_url}")
        
        try:
            async with self.session.get(archive_url) as response:
                if response.status != 200:
                    logger.warning(f"❌ Erreur HTTP {response.status} pour {archive_url}")
                    return set()
                
                archive_data = await response.read()
                logger.info(f"✅ Archive téléchargée: {len(archive_data):,} bytes")
                
                return await self._extract_and_process_archive(archive_data, category_name)
                
        except asyncio.TimeoutError:
            logger.error(f"❌ Timeout lors du téléchargement de {archive_url}")
        except Exception as e:
            logger.error(f"❌ Erreur lors du téléchargement de {archive_url}: {e}")
            
        return set()

    async def _extract_and_process_archive(self, archive_data: bytes, category_name: str) -> Set[str]:
        """Extrait et traite le contenu de l'archive"""
        domains = set()
        
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_data), mode='r:gz') as tar:
                # Chercher le fichier 'domains' dans l'archive
                domains_file = None
                for member in tar.getmembers():
                    if member.name.endswith('/domains') or member.name == 'domains':
                        domains_file = member
                        break
                
                if not domains_file:
                    logger.warning(f"❌ Fichier 'domains' non trouvé dans l'archive {category_name}")
                    return set()
                
                extracted_file = tar.extractfile(domains_file)
                if extracted_file:
                    content = extracted_file.read().decode('utf-8', errors='ignore')
                    total_lines = len(content.split('\n'))
                    logger.info(f"📄 Fichier domains: {total_lines:,} lignes totales")
                    
                    domains = await self._process_domains_content(content)
                    logger.info(f"✅ Domaines valides extraits: {len(domains):,}")
                    
        except Exception as e:
            logger.error(f"❌ Erreur de traitement de l'archive {category_name}: {e}")
            
        return domains

    async def _process_domains_content(self, content: str) -> Set[str]:
        """Traite le contenu du fichier domains avec nettoyage avancé"""
        domains = set()
        invalid_count = 0
        
        for line_num, line in enumerate(content.split('\n'), 1):
            # Supprimer les commentaires
            line = re.sub(r'#.*', '', line)
            line = line.strip().lower()
            line = line.replace('\r', '')
            
            if not line:
                continue
                
            # Ignorer les adresses IP
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
                continue
                
            # Ignorer les lignes avec des caractères spéciaux problématiques
            if re.search(r'[\*\(\)\[\]{}\\$?|]|https?://|//', line):
                continue
                
            # Nettoyer les préfixes et suffixes communs
            line = re.sub(r':\d+$', '', line)  # Supprimer les ports
            line = re.sub(r'/.*$', '', line)   # Supprimer les chemins
            line = re.sub(r'^[\|\*\^]+', '', line)  # Supprimer les préfixes de filtres
            line = re.sub(r'[\^\*]+$', '', line)    # Supprimer les suffixes de filtres
            
            # Nettoyer les espaces et caractères invisibles
            line = line.strip()
            
            if not line:
                continue
                
            # Validation finale avec notre fonction stricte
            if self._is_valid_domain(line):
                domains.add(line)
            else:
                invalid_count += 1
                if invalid_count <= 10:  # Logger seulement les premiers exemples
                    logger.debug(f"Ligne {line_num} ignorée (invalide): '{line}'")
        
        if invalid_count > 10:
            logger.info(f"⚠️ {invalid_count:,} domaines invalides ignorés au total")
            
        return domains

    def _remove_redundant_subdomains(self, domains: Set[str]) -> Set[str]:
        """
        Supprime les sous-domaines redondants quand le domaine parent est déjà présent
        Évite la sur-optimisation qui pourrait créer des règles trop larges
        """
        sorted_domains = sorted(domains)
        filtered = set()
        
        for domain in sorted_domains:
            # Vérifier si un domaine parent existe déjà
            is_redundant = False
            domain_parts = domain.split('.')
            
            # Chercher les domaines parents possibles (mais pas trop génériques)
            for i in range(1, len(domain_parts) - 1):  # Ne pas aller jusqu'au TLD seul
                parent = '.'.join(domain_parts[i:])
                if parent in filtered and len(parent.split('.')) >= 2:
                    is_redundant = True
                    break
            
            if not is_redundant:
                filtered.add(domain)
        
        removed_count = len(domains) - len(filtered)
        if removed_count > 0:
            logger.info(f"🔧 Sous-domaines redondants supprimés: {removed_count:,}")
            
        return filtered

    def _convert_to_adguard_format(self, domains: Set[str]) -> List[str]:
        """Convertit les domaines au format AdGuardHome"""
        # Supprimer les sous-domaines redondants
        optimized_domains = self._remove_redundant_subdomains(domains)
        
        # Convertir au format AdGuard
        adguard_rules = []
        for domain in sorted(optimized_domains):
            # Double vérification avant de créer la règle
            if self._is_valid_domain(domain):
                adguard_rules.append(f"||{domain}^")
            else:
                logger.warning(f"⚠️ Domaine invalide ignoré lors de la conversion: {domain}")
        
        return adguard_rules

    async def process_category(self, category_config: Dict) -> Tuple[str, int]:
        """Traite une catégorie de domaines"""
        category_name = category_config['name']
        logger.info(f"🔄 Traitement de la catégorie: {category_name}")
        
        domains = await self.download_and_extract_archive(category_name)
        
        if not domains:
            logger.warning(f"❌ Aucun domaine trouvé pour {category_name}")
            return category_name, 0

        logger.info(f"📥 Domaines bruts extraits: {len(domains):,}")
        
        # Conversion au format AdGuard avec validation stricte
        adguard_rules = self._convert_to_adguard_format(domains)
        
        if not adguard_rules:
            logger.warning(f"❌ Aucune règle valide générée pour {category_name}")
            return category_name, 0
        
        # Sauvegarde
        output_path = await self._save_adguard_list(category_config, adguard_rules)
        
        logger.info(f"✅ {category_name} terminé: {len(adguard_rules):,} règles sauvées dans {output_path}")
        return category_name, len(adguard_rules)

    async def _save_adguard_list(self, category_config: Dict, rules: List[str]) -> Path:
        """Sauvegarde la liste au format AdGuardHome"""
        output_filename = category_config.get('output_filename', f"adguardhome_{category_config['name']}")
        
        # Créer le dossier de catégorie
        category_dir = self.output_dir / category_config['name']
        category_dir.mkdir(exist_ok=True)
        
        final_path = category_dir / output_filename
        
        # Générer l'en-tête
        header = self._generate_header(category_config, len(rules))
        
        # Assembler le contenu final
        content = header + '\n' + '\n'.join(rules) + '\n'
        
        # Vérifier la taille du fichier
        max_size = self.config['output'].get('max_file_size', 104857600)  # 100MB par défaut
        if len(content.encode('utf-8')) > max_size:
            logger.warning(f"⚠️ Fichier {final_path} dépasse la taille limite ({max_size:,} bytes)")
            # TODO: Implémenter la division en plusieurs fichiers si nécessaire
        
        # Sauvegarder
        with open(final_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        file_size = final_path.stat().st_size
        logger.info(f"💾 Fichier sauvegardé: {final_path} ({file_size:,} bytes)")
        
        return final_path

    def _generate_header(self, category_config: Dict, rule_count: int) -> str:
        """Génère l'en-tête du fichier AdGuardHome"""
        now = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
        
        header = f"""! Title: {category_config.get('title', category_config['name'])} - AdGuard
! Description: {category_config.get('description', 'Liste noire convertie depuis UT-Capitole')}
! Homepage: https://github.com/stenley77/liste-univ-tls1
! Source: {self.base_url}{category_config['name']}.tar.gz
! Rules count: {rule_count:,}
! Updated: {now}
! Expires: 7 days
!"""
        return header

    async def run(self) -> Dict[str, int]:
        """Lance la conversion de toutes les catégories"""
        logger.info("🚀 Début de la conversion des listes noires UT-Capitole vers AdGuardHome")
        
        results = {}
        total_start_time = asyncio.get_event_loop().time()
        
        for category_config in self.config['categories']:
            try:
                category_name, rule_count = await self.process_category(category_config)
                results[category_name] = rule_count
            except Exception as e:
                logger.error(f"❌ Erreur lors du traitement de {category_config.get('name', 'unknown')}: {e}")
                results[category_config.get('name', 'unknown')] = 0
        
        # Statistiques finales
        total_time = asyncio.get_event_loop().time() - total_start_time
        total_rules = sum(results.values())
        successful_categories = sum(1 for count in results.values() if count > 0)
        
        logger.info("=" * 60)
        logger.info("📊 RÉSULTATS FINAUX:")
        for category, count in results.items():
            status = "✅" if count > 0 else "❌"
            logger.info(f"  {status} {category}: {count:,} règles")
        
        logger.info("=" * 60)
        logger.info(f"📈 TOTAL: {total_rules:,} règles générées")
        logger.info(f"✅ Catégories réussies: {successful_categories}/{len(results)}")
        logger.info(f"⏱️ Temps total: {total_time:.2f}s")
        logger.info("🎉 Conversion terminée avec succès!")
        
        return results

async def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Convertit les listes noires UT-Capitole vers AdGuardHome")
    parser.add_argument("--verbose", "-v", action="store_true", help="Mode verbeux")
    parser.add_argument("--config", "-c", default="src/config.yaml", help="Chemin du fichier de configuration")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("🔍 Mode verbeux activé")
    
    try:
        async with BlacklistConverter(args.config) as converter:
            results = await converter.run()
            
            # Code de retour: succès si au moins une catégorie a généré des règles
            return 0 if any(results.values()) else 1
            
    except KeyboardInterrupt:
        logger.info("❌ Interruption par l'utilisateur")
        return 1
    except Exception as e:
        logger.error(f"❌ Erreur fatale: {e}")
        return 1

if __name__ == "__main__":
    exit(asyncio.run(main()))
