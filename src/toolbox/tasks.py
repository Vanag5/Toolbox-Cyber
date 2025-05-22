import os
from celery import Celery


def create_celery(app=None):
    """
    Create and configure a Celery instance.
    If a Flask app is provided, integrate Celery with the app context.
    """
    celery = Celery(
        'tasks',
        broker=os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0'),
        backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0'),
        include=['toolbox.tasks']
    )

    # Update Celery configurations
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
    )

    # Integrate with Flask app context if provided
    if app:
        celery.conf.update(app.config)
        TaskBase = celery.Task

        class ContextTask(TaskBase):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return TaskBase.__call__(self, *args, **kwargs)

        celery.Task = ContextTask

    return celery


# Create a global Celery instance
celery = create_celery()
