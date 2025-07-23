from django.apps import AppConfig


class PlugConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'plug'

class PlugConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'plug'

    def ready(self):
        import plug.signals


