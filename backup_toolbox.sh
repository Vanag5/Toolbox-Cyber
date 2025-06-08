#!/bin/bash

# === CONFIGURATION ===
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="./backup/$TIMESTAMP"
DB_CONTAINER="toolbox-cyber_db_1"              
DB_NAME="toolbox_db"
DB_USER="postgres"
VOLUMES=("postgres_data" "minio_data" "scan_reports")  # Volumes Docker à sauvegarder
CONFIG_FILES=("docker-compose.yml" "Dockerfile")
IMAGE_NAME="toolbox-cyber"  # Nom de l'image Docker à sauvegarder (si besoin)

# === CRÉATION DU DOSSIER DE BACKUP ===
mkdir -p "$BACKUP_DIR"

echo "📦 Sauvegarde démarrée à $TIMESTAMP"

# === 1. Sauvegarde de la base PostgreSQL ===
echo "🛢️  Sauvegarde de la base de données..."
docker exec -t "$DB_CONTAINER" pg_dump -U "$DB_USER" "$DB_NAME" > "$BACKUP_DIR/postgres_backup.sql"

# === 2. Sauvegarde des volumes ===
for volume in "${VOLUMES[@]}"; do
  echo "📁 Sauvegarde du volume : $volume"
  docker run --rm \
    -v "${volume}":/volume \
    -v "$BACKUP_DIR":/backup \
    alpine \
    tar czf "/backup/${volume}_backup.tar.gz" -C /volume .
done

# === 3. Sauvegarde des fichiers de config ===
echo "⚙️  Sauvegarde des fichiers de configuration..."
tar czf "$BACKUP_DIR/config_backup.tar.gz" "${CONFIG_FILES[@]}"

# === 4. Sauvegarde de l'image Docker (optionnel) ===
echo "🐳 Sauvegarde de l'image Docker '$IMAGE_NAME'..."
docker save "$IMAGE_NAME" | gzip > "$BACKUP_DIR/${IMAGE_NAME}_image.tar.gz"

echo "✅ Sauvegarde terminée dans $BACKUP_DIR"
