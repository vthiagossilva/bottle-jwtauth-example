from bottle import request, response
import hashlib,base64,time, hmac,json

from models import Users

# Uma chave privada criada por uma função hash
# Esta chave será utilizada para criptografar e descriptografar a assinatura do seu JWT
# portanto, você PRECISA mantê-la em sigilo. Se utilizar git, certifique-se de utilizar um
# arquivo .env listado em .gitignore
  
secret_key = '52d3f853c19f8b63c0918c126422aa2d99b1aef33ec63d41dea4fadf19406e54'

# Função responsável por criar um novo usuário
# "data" espera um dicionário no formato
#       {"username": ,"password": ,"name": } 
#  Seu retorno é uma tupla contendo um dicionário e um inteiro (status http)
def new_user(data):
    # Verifica se os dados exigidos são fornecidos
    if data.get('username') and data.get('password') and data.get('name'):
        # Verifica se o usuário já está registrado
        if not Users.select().where(Users.username == data["username"]):
            # Insere um novo usuário no banco de dados, note que password é salvo como
            # o resultado de uma função de hash, no caso, SHA512
            Users.insert(
                username = data["username"],
                password = hashlib.sha512( (data['password']).encode('utf-8') ).hexdigest(),
                name = data["name"]
            ).execute()
            # Gera um JWT para logar o usuário assim que ele é criado
            result = make_login(data)
            
            return result
        # 409, "conflito"
        return {"error":"Usuário existente"}, 409
    # 400, "Requisição mal construída"
    return {"error":"Dados insuficientes"}, 400


# Função responsável por verificar as credenciais enviadas e gerar o JWT
# data espera um dicionário no formato
#       {"username": ,"password": }
#  Seu retorno é uma tupla contendo um dicionário e um inteiro (status http)
def make_login(data):
    # Verifica se os campos username e password existem nos dados da requisição
    try:
        username = data['username']
        # hashlib.sha512 obtém a senha enviada como o comparador com a senha gravada no banco de dados
        # espera: uma criptografia SHA512
        password = hashlib.sha512( (data['password']).encode('utf-8') ).hexdigest()
    except KeyError:
        username, password = False, False
    if username and password:
        # A cláusula where() se encarrega de verificar se existe no banco de dados algum usuário com
        # username e senha correspondentes ao submetido
        u = Users.select().where((Users.username == username) & (Users.password == password))
        if u:
            # Aqui começa a criação do JWT Token
            # Conforme o header mostra, a algorítmo de criptografia escolhido para validação da
            # assinatura é o SHA256
            header = json.dumps({
                "typ":"JWT",
                "alg":"HS256"
            }).encode()
            # O corpo do token contém o username, o tipo de usuário e o timestamp de expiração do token
            payload = json.dumps({
                "username":u[0].username,
                "name":u[0].name,
                # time.time() retorna um float que representa o número de *segundos* desde o início da Era Unix
                "exp":str(time.time() + 24 * 60 * 60) # Um dia
            }).encode()

            # Codifica o header e payload em base64, como se espera em um JWT Token
            b64_header = base64.urlsafe_b64encode(header).decode()
            b64_payload = base64.urlsafe_b64encode(payload).decode()

            # Cria uma assinatura criptografada em SHA256 utilizando a chave secreta
            signature = hmac.new(
                key=secret_key.encode(), 
                msg=f'{b64_header}.{b64_payload}'.encode(),
                digestmod=hashlib.sha256
            ).digest()
            
            # Contrói o JWT concatenando header, payload e assinatura com .
            jwt = f'{b64_header}.{b64_payload}.{base64.urlsafe_b64encode(signature).decode()}'

            # Dicionário contendo o JWT e o status OK
            return {"jwt":jwt}, 200
    # Verificação de username x senha com falha, status "proibido"
    return {"error":"Nome de usuário ou senha incorretos"}, 401


# Ao receber do cliente o JWT, esta função irá validá-lo ou não
# Token espera uma lista (ou tupla) com ['Bearer',JWT], sendo JWT o token propriamente dito
def check_jwt(token):
    jwt = False
    # Verifica se o cabeçalho Authorization da requisição está no formato esperado
    if len(token) == 2 and token[0] == 'Bearer':
        jwt = token[1]
    if jwt:
        try:
            # Usa-se o contatenador . para gerar uma lista retornando header, payload e signature em
            # codificação base64
            b64_header, b64_payload, b64_signature = jwt.split('.')

            # b64_signature_checker armazena a assinatura descriptografada
            b64_signature_checker = base64.urlsafe_b64encode(
                hmac.new(
                    key=secret_key.encode(), 
                    msg=f'{b64_header}.{b64_payload}'.encode(), 
                    digestmod=hashlib.sha256
                ).digest()
            ).decode()

            # Verifica se a autenticidade do token comparando a assinatura descriptografada com o 
            # resultado da concatenação '{header}.{payload}' 
            if b64_signature_checker == b64_signature:
                # payload armazena um dicionário com chave:valor do JWT.payload
                payload = json.loads(base64.urlsafe_b64decode(b64_payload))

                # Verifica se o token ainda é válido. Se não, retorna Proibido (401)
                if payload.get('exp') and float(payload['exp']) < time.time():
                    return {"error":"Token expirado"}, 401

                # Se todas as verificações passarem, retorna o payload e OK (200)
                return payload, 200
            
            # Se não passar na verificação da assinatura, retorna Proibido (401)
            return {"error":"Assinatura inválida"}, 401
        except:
            pass
    
    # Caso em que o Token não está no formato esperado. Por exemplo, o cabeçalho Autorization está como
    # Basic {token}
    return {"error":"Solicitação inválida"}, 401





# Este é um decorador para rotas que necessitam de login
def login_required(f):
    def wrapper(*args, **kwargs):
        # Verifica a existência do cabeçalho Authorization
        token = request.get_header('Authorization')
        if token:
            # Torna o valor do cabeçalho Authorization uma lista para ser analisado por check_jwt
            token = token.split(' ')
            payload, status = check_jwt(token)

            # Para qualquer falha, retorna para o cliente o erro e como se autenticar
            if status != 200:
                response.body, response.status = payload, status # Neste caso, payload é uma mensagem de erro
                response.set_header("WWW-Authenticate","Bearer")
                return  response

            # Em caso de sucesso na verificação, obtém o usuário autenticado e retorna a instância para
            # a função decorada
            user = Users.get_or_none(Users.username == payload["username"])
            if user:
                return f(user, *args, **kwargs)
            response.body = json.dumps({"error":"Usuário não existe mais"})
        
        # Caso não exista o cabeçalho Authorization, retorna Proibido (401) e como o usuário pode se autenticar
        response.status = 401
        response.set_header("WWW-Authenticate","Bearer")
        return response
    return wrapper