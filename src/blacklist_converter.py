name: Update AdGuard Blocklists

on:
  schedule:
    - cron: '0 12 * * 6'  # Samedi à 12h UTC
  workflow_dispatch:
  push:
    branches: [ main, master ]  # Support des deux noms de branche
    paths: 
      - 'src/**'
      - '.github/workflows/**'

jobs:
  update-blocklists:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          fetch-depth: 1

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
          # Suppression du cache pour éviter l'erreur
          # cache: 'pip'

      - name: Verify repository structure
        run: |
          echo "📁 Structure du repository:"
          find . -type f -name "*.txt" -o -name "*.py" -o -name "*.yaml" -o -name "*.yml" | head -20
          echo ""
          echo "📄 Contenu du dossier racine:"
          ls -la
          echo ""
          echo "📄 Contenu du dossier src (si existe):"
          if [ -d "src" ]; then
            ls -la src/
          else
            echo "❌ Dossier src non trouvé"
          fi

      - name: Create missing files if needed
        run: |
          # Créer la structure des dossiers
          mkdir -p src output/adguard
          
          # Créer requirements.txt s'il n'existe pas
          if [ ! -f "src/requirements.txt" ]; then
            echo "🔧 Création du fichier requirements.txt..."
            cat > src/requirements.txt << 'EOF'
          aiohttp>=3.9.0
          PyYAML>=6.0.1
          aiofiles>=23.0.0
          EOF
          fi
          
          # Créer config.yaml s'il n'existe pas
          if [ ! -f "src/config.yaml" ]; then
            echo "🔧 Création du fichier config.yaml..."
            cat > src/config.yaml << 'EOF'
          source:
            base_url: "ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/"

          output:
            directory: "output/adguard"
            max_file_size: 104857600
            generate_master: false

          categories:
            - name: "adult"
              title: "Adult Content - UT Capitole"
              description: "Sites à contenu adulte bloqués par l'Université Toulouse 1 Capitole"
              output_filename: "adguardhome_adult"

            - name: "malware"
              title: "Malware - UT Capitole"
              description: "Sites malveillants identifiés par l'Université Toulouse 1 Capitole"
              output_filename: "adguardhome_malware"

            - name: "mixed_adult"
              title: "Mixed Adult Content - UT Capitole"
              description: "Contenu mixte adulte de l'Université Toulouse 1 Capitole"
              output_filename: "adguardhome_mixed_adult"

            - name: "ddos"
              title: "DDoS Sources - UT Capitole"
              description: "Sources de DDoS identifiées par l'Université Toulouse 1 Capitole"
              output_filename: "adguardhome_ddos"
          EOF
          fi

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          if [ -f "src/requirements.txt" ]; then
            pip install -r src/requirements.txt
          else
            # Installation directe si le fichier n'existe pas
            pip install aiohttp PyYAML aiofiles
          fi

      - name: Download and setup converter script
        run: |
          # Si le script n'existe pas, le créer
          if [ ! -f "src/blacklist_converter.py" ]; then
            echo "🔧 Création du script convertisseur..."
            cat > src/blacklist_converter.py << 'EOF'
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

          # Configuration du logging
          logging.basicConfig(
              level=logging.INFO,
              format='%(asctime)s - %(levelname)s - %(message)s'
          )
          logger = logging.getLogger(__name__)

          class BlacklistConverter:
              def __init__(self, config_path: str = "src/config.yaml"):
                  try:
                      with open(config_path, 'r', encoding='utf-8') as f:
                          self.config = yaml.safe_load(f)
                  except FileNotFoundError:
                      # Configuration par défaut si fichier absent
                      self.config = {
                          'source': {'base_url': 'ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/'},
                          'output': {'directory': 'output/adguard', 'max_file_size': 104857600},
                          'categories': [
                              {'name': 'adult', 'title': 'Adult Content', 'output_filename': 'adguardhome_adult'},
                              {'name': 'malware', 'title': 'Malware', 'output_filename': 'adguardhome_malware'},
                          ]
                      }
                  
                  self.session = None
                  self.base_url = self.config['source']['base_url']
                  self.output_dir = Path(self.config['output']['directory'])
                  self.output_dir.mkdir(parents=True, exist_ok=True)

              async def __aenter__(self):
                  connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
                  timeout = aiohttp.ClientTimeout(total=300, connect=30)
                  self.session = aiohttp.ClientSession(
                      connector=connector,
                      timeout=timeout,
                      headers={'User-Agent': 'AdGuard-Blacklist-Converter/2.0'}
                  )
                  return self

              async def __aexit__(self, exc_type, exc_val, exc_tb):
                  if self.session:
                      await self.session.close()

              async def download_and_extract_archive(self, category_name: str) -> Set[str]:
                  archive_url = f"{self.base_url}{category_name}.tar.gz"
                  logger.info(f"📥 Téléchargement de {archive_url}")
                  
                  try:
                      async with self.session.get(archive_url) as response:
                          if response.status != 200:
                              logger.warning(f"❌ Erreur HTTP {response.status} pour {archive_url}")
                              return set()
                          
                          archive_data = await response.read()
                          logger.info(f"✅ Archive téléchargée: {len(archive_data)} bytes")
                          
                          return await self._extract_and_process_archive(archive_data, category_name)
                          
                  except Exception as e:
                      logger.error(f"❌ Erreur lors du téléchargement de {archive_url}: {e}")
                      return set()

              async def _extract_and_process_archive(self, archive_data: bytes, category_name: str) -> Set[str]:
                  domains = set()
                  
                  try:
                      with tarfile.open(fileobj=io.BytesIO(archive_data), mode='r:gz') as tar:
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
                              logger.info(f"📄 Fichier domains: {total_lines} lignes totales")
                              
                              domains = await self._fast_process_domains(content)
                              
                  except Exception as e:
                      logger.error(f"❌ Erreur de traitement de l'archive {category_name}: {e}")
                      
                  return domains

              async def _fast_process_domains(self, content: str) -> Set[str]:
                  domains = set()
                  
                  for line in content.split('\n'):
                      line = re.sub(r'#.*', '', line)
                      line = line.strip().lower()
                      line = line.replace('\r', '')
                      
                      if not line:
                          continue
                          
                      if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
                          continue
                          
                      if re.search(r'[\*\(\)\[\]{}\\$?|]|https?://|//', line):
                          continue
                          
                      line = re.sub(r':\d+$', '', line)
                      line = re.sub(r'/.*$', '', line)
                      line = re.sub(r'^[\|\*]+', '', line)
                      line = re.sub(r'[\^\*]+$', '', line)
                      
                      if not '.' in line:
                          continue
                          
                      if not re.match(r'^[a-z0-9.-]+$', line):
                          continue
                          
                      if '..' in line:
                          continue
                          
                      if len(line) < 4 or len(line) > 253:
                          continue
                          
                      parts = line.split('.')
                      if len(parts) < 2 or len(parts[-1]) < 2 or len(parts[-2]) < 2:
                          continue
                          
                      domains.add(line)
                      
                  return domains

              def _convert_to_adguard_format(self, domains: Set[str]) -> List[str]:
                  adguard_rules = []
                  for domain in sorted(domains):
                      adguard_rules.append(f"||{domain}^")
                  return adguard_rules

              async def process_category(self, category_config: Dict) -> Tuple[str, int]:
                  category_name = category_config['name']
                  logger.info(f"Processing {category_name}...")
                  
                  domains = await self.download_and_extract_archive(category_name)
                  
                  if not domains:
                      logger.warning(f"❌ Aucun domaine trouvé pour {category_name}")
                      return category_name, 0

                  logger.info(f"📥 Domaines extraits: {len(domains)}")
                  adguard_rules = self._convert_to_adguard_format(domains)
                  
                  output_path = await self._save_adguard_list(category_config, adguard_rules)
                  
                  logger.info(f"✅ {category_name} terminé: {len(adguard_rules)} règles")
                  return category_name, len(adguard_rules)

              async def _save_adguard_list(self, category_config: Dict, rules: List[str]) -> Path:
                  output_filename = category_config.get('output_filename', f"adguardhome_{category_config['name']}")
                  output_path = self.output_dir / category_config['name']
                  output_path.mkdir(exist_ok=True)
                  
                  final_path = output_path / output_filename
                  
                  header = self._generate_header(category_config, len(rules))
                  content = header + '\n' + '\n'.join(rules) + '\n'
                  
                  with open(final_path, 'w', encoding='utf-8') as f:
                      f.write(content)
                  
                  logger.info(f"✅ Fichier sauvegardé: {final_path}")
                  return final_path

              def _generate_header(self, category_config: Dict, rule_count: int) -> str:
                  now = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
                  
                  header = f"""! Title: {category_config.get('title', category_config['name'])} - AdGuard
          ! Description: {category_config.get('description', 'Liste noire convertie depuis UT-Capitole')}
          ! Homepage: https://github.com/stenley77/liste-univ-tls1
          ! Source: {self.base_url}{category_config['name']}.tar.gz
          ! Rules count: {rule_count}
          ! Updated: {now}
          ! Expires: 7 days
          !"""
                  return header

              async def run(self) -> Dict[str, int]:
                  logger.info("🚀 Début de la conversion des listes noires UT-Capitole")
                  
                  results = {}
                  
                  for category_config in self.config['categories']:
                      category_name, rule_count = await self.process_category(category_config)
                      results[category_name] = rule_count
                  
                  total_rules = sum(results.values())
                  logger.info(f"📊 TOTAL: {total_rules:,} règles")
                  logger.info("🎉 Conversion terminée avec succès")
                  return results

          async def main():
              try:
                  async with BlacklistConverter() as converter:
                      results = await converter.run()
                      return 0 if any(results.values()) else 1
              except Exception as e:
                  logger.error(f"❌ Erreur fatale: {e}")
                  return 1

          if __name__ == "__main__":
              exit(asyncio.run(main()))
          EOF
            chmod +x src/blacklist_converter.py
          fi

      - name: Create output directories
        run: |
          mkdir -p output/adguard/adult
          mkdir -p output/adguard/malware
          mkdir -p output/adguard/mixed_adult
          mkdir -p output/adguard/ddos
          mkdir -p output/adguard/phishing

      - name: Run blacklist converter
        run: |
          cd ${{ github.workspace }}
          python src/blacklist_converter.py
        env:
          PYTHONPATH: ${{ github.workspace }}

      - name: Verify output files
        run: |
          echo "🔍 Vérification des fichiers générés..."
          find output/adguard -name "adguardhome_*" -type f | while read file; do
            echo "📄 $file:"
            echo "  Taille: $(stat -c%s "$file" | numfmt --to=iec)"
            echo "  Règles: $(grep -c "^||.*\^$" "$file" 2>/dev/null || echo "0")"
            echo "  Premières lignes:"
            head -10 "$file" | sed 's/^/    /'
            echo ""
          done

      - name: Generate statistics and README
        run: |
          echo "# 🛡️ AdGuard Blocklists - UT Capitole" > output/adguard/README.md
          echo "" >> output/adguard/README.md
          echo "Listes de blocage AdGuardHome générées à partir des [listes noires de l'Université Toulouse 1 Capitole](ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/)." >> output/adguard/README.md
          echo "" >> output/adguard/README.md
          echo "**Dernière mise à jour:** $(date -u '+%Y-%m-%d %H:%M UTC')" >> output/adguard/README.md
          echo "" >> output/adguard/README.md
          echo "## 📊 Statistiques" >> output/adguard/README.md
          echo "" >> output/adguard/README.md
          echo "| Catégorie | Fichier | Règles | Taille |" >> output/adguard/README.md
          echo "|-----------|---------|--------|--------|" >> output/adguard/README.md
          
          find output/adguard -name "adguardhome_*" -type f | while read file; do
            category=$(basename $(dirname "$file"))
            filename=$(basename "$file")
            rules=$(grep -c "^||.*\^$" "$file" 2>/dev/null || echo "0")
            size=$(stat -c%s "$file" | numfmt --to=iec)
            rel_path="${category}/${filename}"
            echo "| $category | [\`$filename\`]($rel_path) | $rules | $size |" >> output/adguard/README.md
          done
          
          echo "" >> output/adguard/README.md
          echo "## 🚀 Utilisation" >> output/adguard/README.md
          echo "" >> output/adguard/README.md
          echo "### URLs pour AdGuardHome:" >> output/adguard/README.md
          echo "" >> output/adguard/README.md
          
          find output/adguard -name "adguardhome_*" -type f | while read file; do
            category=$(basename $(dirname "$file"))
            filename=$(basename "$file")
            echo "**$category:** \`https://raw.githubusercontent.com/${{ github.repository }}/main/output/adguard/$category/$filename\`" >> output/adguard/README.md
            echo "" >> output/adguard/README.md
          done

      - name: Setup Git config
        run: |
          git config --global user.name "github-actions[bot]"
          git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com"

      - name: Commit and push changes
        run: |
          git add output/
          git add src/ 2>/dev/null || true  # Ajouter src si modifié
          
          if git diff --cached --quiet; then
            echo "⚠️ Aucun changement détecté"
          else
            changed_files=$(git diff --cached --name-only | wc -l)
            echo "✅ Changements détectés dans $changed_files fichier(s):"
            git diff --cached --name-status
            
            commit_msg="🤖 Update AdGuard Home blocklists [$(date +'%Y-%m-%d %H:%M UTC')]"
            git commit -m "$commit_msg"
            git push
            
            echo "✅ Listes mises à jour et publiées avec succès"
          fi
