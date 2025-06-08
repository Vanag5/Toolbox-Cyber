#!/bin/bash
set -e  # Stop on any error

# === CONFIGURATION ===
BACKUP_TIMESTAMP=$1  # L'utilisateur doit fournir le timestamp du dossier de sauvegarde
BACKUP_DIR="./backup/$BACKUP_TIMESTAMP"
DB_CONTAINER="toolbox-cyber_db_1"  # Adapter au nom réel
DB_NAME="toolbox_db"
DB_USER="postgres"
VOLUMES=("postgres_data" "minio_data" "scan_reports")
IMAGE_NAME="toolbox-cyber"

# === VÉRIFICATIONS ===
if [ -z "$BACKUP_TIMESTAMP" ]; then
  echo "❌ Usage: $0 <backup_timestamp>"
  echo "👉 Exemple: $0 20250608_153005"
  exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
  echo "❌ Dossier de backup non trouvé: $BACKUP_DIR"
  exit 1
fi

echo "♻️ Restauration depuis la sauvegarde: $BACKUP_TIMESTAMP"

# === 1. Restauration de l'image Docker ===
if [ -f "$BACKUP_DIR/${IMAGE_NAME}_image.tar.gz" ]; then
  echo "🐳 Restauration de l'image Docker '$IMAGE_NAME'..."
  gunzip -c "$BACKUP_DIR/${IMAGE_NAME}_image.tar.gz" | docker load
else
  echo "⚠️  Image Docker non trouvée, sautée."
fi

# === 2. Restauration des volumes ===
for volume in "${VOLUMES[@]}"; do
  echo "📁 Restauration du volume : $volume"
  docker volume create "$volume"
  docker run --rm \
    -v "$volume":/volume \
    -v "$BACKUP_DIR":/backup \
    alpine \
    sh -c "rm -rf /volume/* && tar xzf /backup/${volume}_backup.tar.gz -C /volume"
done

# === 3. Restauration des fichiers de configuration ===
if [ -f "$BACKUP_DIR/config_backup.tar.gz" ]; then
  echo "⚙️  Restauration des fichiers de configuration..."
  tar xzf "$BACKUP_DIR/config_backup.tar.gz" -C .
else
  echo "⚠️  Fichiers de config non trouvés, sautés."
fi

# === 4. Restauration de la base PostgreSQL ===
if [ -f "$BACKUP_DIR/postgres_backup.sql" ]; then
  echo "🛢️  Restauration de la base de données PostgreSQL..."
  docker cp "$BACKUP_DIR/postgres_backup.sql" "$DB_CONTAINER":/tmp/postgres_backup.sql
  docker exec -u postgres "$DB_CONTAINER" psql -d "$DB_NAME" -f /tmp/postgres_backup.sql
else
  echo "⚠️  Fichier de backup PostgreSQL non trouvé, base non restaurée."
fi

echo "✅ Restauration terminée !"
