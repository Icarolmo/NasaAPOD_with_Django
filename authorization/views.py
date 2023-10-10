from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from . import tokens, info
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import authenticate, login, logout
import smtplib
from email.message import Message
from django.contrib.auth.decorators import login_required
import requests

# Página inicial do site
def index(request):
    return render(request, 'authorization/index.html')

# Página sobre o site
def sobre(request):
    return render(request, 'authorization/sobre.html')

# Página de login: autenticação de usuário caso não esteja logado.
# Caso não tenha conta cadastrada pode ser redirecionado para a página de cadastro clicando em registrar-se. 
# Caso esteja logado, redireciona para a página inicial
def entrar(request):

    # Verifica se o usuário está logado, caso esteja redireciona para a página inicial
    if request.user.is_authenticated:
        return redirect('index')

    # Verifica se o método de requisição é POST, caso seja, tenta autenticar o usuário
    if request.method == 'POST':    
        username = request.POST['username']
        senha = request.POST['senha']

        usuario = authenticate(username=username,password=senha)

        if usuario is not None:
            if usuario.is_active == True:
                login(request, usuario)
                messages.success(request, 'Login realizado com sucesso.')
                return render(request, 'authorization/index.html')
            else:
                messages.error(request, 'Pendente ativação da conta. Por favor verifique o e-mail usado no cadastro.')
                return redirect('entrar')
        else:
            messages.error(request, 'Credenciais de usuário inválidas/inexistêntes.')
            return redirect('entrar')
    
    return render(request, 'authorization/entrar.html')

# Página de cadastro: criação de usuário 
# Verifica se o usuário está logado, caso esteja redireciona para a página inicial
def cadastro(request):

    if request.user.is_authenticated:
        messages.error(request, 'Usuário já logado. Para cadastrar um novo usuário, por favor, deslogue-se.')
        return redirect('index')

    # Verifica se o método de requisição é POST, caso seja, tenta criar o usuário com dados da requisição
    if request.method == 'POST':

        nome = request.POST['nome']
        sobrenome = request.POST['sobrenome']
        username = request.POST['username']
        email = request.POST['email']
        senha = request.POST['senha']

        meu_usuario = User.objects.create_user(username=username,email=email,password=senha)
        meu_usuario.first_name = nome
        meu_usuario.last_name = sobrenome
        meu_usuario.is_active = False
        meu_usuario.save()

        # Pendente: Implementar método assíncrono para envio de e-mail com agradecimento e informações sobre a conta criada
        # Justificativa: Demora excessiva na conclusão do cadastro pelo envio dos dois e-mails
        # Objetivo: Reduzir o tempo de resposta da requisição de cadastro retornando a conclusão do cadastro 
        # e enviando o e-mail com as informações sobre a conta criada em segundo plano

        # EMAIL com agradecimento e informações sobre a conta criada
        corpo_email_agradecimento = info.CORPO_EMAIL(nome, username, senha)
        msg1 = Message()
        msg1['Subject'] = info.ASSUNTO['EMAIL_AGRADECIMENTO']
        msg1['From'] = info.REMETENTE
        msg1['To'] = email
        password = info.SENHA_APP 
        msg1.add_header('Content-Type', 'text/html')
        msg1.set_payload(corpo_email_agradecimento)

        s1 = smtplib.SMTP(info.EMAIL_SMTP)
        s1.starttls()
        s1.login(msg1['From'], password)
        s1.sendmail(msg1['From'], [msg1['To']], msg1.as_string().encode('utf-8'))

        # EMAIL com link de ativação da conta
        current_site = get_current_site(request)
        corpo_email_ativacao = render_to_string('email_confirmacao.html', {
        'nome': meu_usuario.first_name,
        'dominio': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(meu_usuario.pk)),
        'token': tokens.generate_token.make_token(meu_usuario)
        })
        msg2 = Message()
        msg2['Subject'] = info.ASSUNTO['EMAIL_ATIVACAO']
        msg2['From'] = info.REMETENTE
        msg2['To'] = email
        msg2.add_header('Content-Type', 'text/html')
        msg2.set_payload(corpo_email_ativacao)

        s2 = smtplib.SMTP(info.EMAIL_SMTP)
        s2.starttls()
        s2.login(msg2['From'], password)
        s2.sendmail(msg2['From'], [msg2['To']], msg2.as_string().encode('utf-8'))
            

        messages.success(request, 'Usuário cadastrado com sucesso! Para ativar sua conta verifique o link de confirmação que enviamos ao seu email.')
        return redirect('entrar')

    return render(request, 'authorization/cadastro.html')

# Página de logout: desloga o usuário autenticado
def sair(request):
    logout(request)
    messages.success(request, 'Usuário deslogado.')

    return redirect('index')

# Página de ativação de conta: ativa a conta do usuário cadastrado usando o link enviado por e-mail.
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and tokens.generate_token.check_token(myuser,token):
        myuser.is_active = True
        myuser.save()
        messages.success(request, "Sua conta foi ativada! Agora você pode acessar a APOD utilizando seus dados de login.")
        return redirect('entrar')
    else:
        return render(request,'activation_failed.html')
    
# Página da APOD: exibe a imagem do dia da NASA
@login_required
def apod(request):

    if request.method == 'POST':

        response = requests.get(info.APOD_URL+'api_key='+info.API_KEY+'&date='+request.POST['date'])

        if response.status_code == 200:
            return render(request, 'aplication/apod-service.html', { 'response_json': response.json() })

    return render(request, 'aplication/apod.html')