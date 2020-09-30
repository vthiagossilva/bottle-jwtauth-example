from bottle import request, response
import json

from auth import login_required
import auth

# Rota que não necessita de login
def open_route():
    response.body = json.dumps(["Não precisa de login"])

    return response


# Rotas decoradas com @login_required esperam uma requisição com cabeçalho
# Authorization = "Bearer {token}", caso contrário, a requisição retornará Proibido (401)
# e como se autenticar
# Rotas com esse decorador precisam conter um argumento para user, que é uma instância do usuário
# autenticado que pode ser manipulado da forma que for desejada
@login_required
def restrict_route(user):
    response.body = json.dumps(
        {
            "username":user.username,
            "name":user.name
        })
    
    return response


# Função para o login
def make_login():
    data = request.json
    result, status = auth.make_login(data)

    response.body = json.dumps(result)
    response.status = status

    return response


# Função para a criação de um novo usuário
def new_user():
    data = request.json
    result, status = auth.new_user(data)
    
    response.body = json.dumps(result)
    response.status = status

    return response