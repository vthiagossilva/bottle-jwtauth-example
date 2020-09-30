from bottle import app, route, run

from models import Users
import controller

# Configurações das rotas. Todos os callbacks estão no módulo controller
def routes(application):
    # Esta rota não necessita de login
    route("/open-route/", "GET", controller.open_route)
    # Esta é uma rota protegida
    route("/close-route/", "GET", controller.restrict_route)

    # Rota para criar novo usuário
    route("/new-user/", "POST", controller.new_user)
    # Rota para realizar o login
    route("/login/", "POST", controller.make_login)



# Este bloco verifica se o banco de dados existe, se não, o cria junto com nossa única tabela
try:
    f = open('database.db','r')
    f.close()
except:
    Users.create_table()
    
# Inicialização do aplicativo
application = app()
routes(application)

# Normalmente você só deve querer utilizar o que segue em desenvolvimento
run(application, host='0.0.0.0', port=3333, reloader=True, debug=True)