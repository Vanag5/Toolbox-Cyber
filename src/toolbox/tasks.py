from celery import Celery
import subprocess

def create_celery():
    celery = Celery(
        'tasks',
        broker='redis://redis:6379/0',
        backend='redis://redis:6379/0',
        include=['toolbox.tasks']
    )
    
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
    )
    
    return celery

celery = create_celery()
