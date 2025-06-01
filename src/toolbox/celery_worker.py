from toolbox import create_app
from toolbox.celery import celery, init_celery
from toolbox import tasks  # 👈 IMPORTANT : importe les tâches pour les enregistrer

app = create_app()
init_celery(app)
