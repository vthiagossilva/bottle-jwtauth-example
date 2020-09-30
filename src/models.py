# O ORM escolhido para este exemplo é o peewee, principalmente por ser simples e bastante leve
# Naturalmente para os fins deste exemplo a escolha do ORM é completamente livre

from peewee import Model, SqliteDatabase
import peewee

db = SqliteDatabase('database.db')

class Users(Model):
    username = peewee.CharField()
    password = peewee.CharField()
    name = peewee.CharField()
    
    class Meta:
        database = db