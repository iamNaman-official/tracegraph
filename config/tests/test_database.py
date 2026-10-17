from pathlib import Path
from unittest import TestCase

from config.database import database_config


class DatabaseConfigurationTests(TestCase):
    def test_sqlite_is_the_local_default(self):
        config = database_config({}, Path("db.sqlite3"))
        self.assertEqual(config, {"ENGINE": "django.db.backends.sqlite3", "NAME": Path("db.sqlite3")})

    def test_database_url_configures_postgresql_without_exposing_credentials(self):
        config = database_config({
            "DATABASE_URL": "postgresql://trace_user:secret%40value@db.example:5544/trace_db?sslmode=require&connect_timeout=7&ignore_me=yes",
        }, "db.sqlite3")
        self.assertEqual(config, {
            "ENGINE": "django.db.backends.postgresql", "NAME": "trace_db", "USER": "trace_user",
            "PASSWORD": "secret@value", "HOST": "db.example", "PORT": "5544",
            "OPTIONS": {"sslmode": "require", "connect_timeout": "7"},
        })

    def test_postgres_variables_configure_postgresql(self):
        config = database_config({"POSTGRES_DB": "trace_db", "POSTGRES_USER": "trace_user",
                                  "POSTGRES_PASSWORD": "secret", "POSTGRES_HOST": "db",
                                  "POSTGRES_PORT": "5433", "POSTGRES_SSLMODE": "verify-full"}, "db.sqlite3")
        self.assertEqual(config["ENGINE"], "django.db.backends.postgresql")
        self.assertEqual((config["NAME"], config["HOST"], config["PORT"]), ("trace_db", "db", "5433"))
        self.assertEqual(config["OPTIONS"], {"sslmode": "verify-full"})

    def test_database_url_takes_precedence_and_bad_configuration_fails_closed(self):
        config = database_config({"DATABASE_URL": "postgres://u:p@db/main", "POSTGRES_DB": "ignored"}, "db.sqlite3")
        self.assertEqual(config["NAME"], "main")
        for environ in ({"DATABASE_URL": "mysql://db/main"}, {"DATABASE_URL": "postgresql:///missing-host"},
                        {"POSTGRES_USER": "configured-without-database"}):
            with self.subTest(keys=tuple(environ)), self.assertRaises(ValueError):
                database_config(environ, "db.sqlite3")
