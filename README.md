**SafeClinica - Sistema de Monitoramento de Segurança para Clínicas**

## **📌 Visão Geral**
O **SafeClinica** é uma aplicação web para monitoramento de segurança em clínicas médicas, oferecendo:  
✅ Autenticação de usuários com **2FA (Two-Factor Authentication)**  
✅ Registro em tempo real de eventos de segurança (logins, tentativas suspeitas)  
✅ Painel administrativo com dispositivos conectados e histórico de alertas  
✅ Exportação de logs em **CSV/ZIP** para auditoria  

---

## **🚀 Funcionalidades Principais**
### **🔐 Autenticação Segura**
- Login com senha hash (bcrypt)  
- Configuração opcional de **2FA via Google Authenticator**  
- Sessões protegidas com `@login_required`  

### **📊 Painel de Monitoramento**
- Visualização de **dispositivos ativos** (últimos 5 minutos)  
- Tabela de **eventos de segurança** (login, logout, tentativas suspeitas)  
- Filtro por IP/clínica  

### **📤 Exportação de Dados**
- Geração de **relatórios em CSV** (com codificação UTF-8 para Excel)  
- Compactação automática em **ZIP**  

### **⚡ Tempo Real**
- Atualização instantânea de novos eventos via **Socket.IO**  
- Notificações para administradores  

---

## **🖥️ Como Executar o Projeto**
### **Pré-requisitos**
- Python 3.8+  
- Bibliotecas listadas em `requirements.txt`  

### **Passos**
1. Clone o repositório:
   git clone https://github.com/seu-usuario/safeclinica.git
   cd safeclinica

2. Instale as dependências:
   pip install -r requirements.txt

3. Inicie o banco de dados e a aplicação:
   python app.py

4. Acesse no navegador:
   http://localhost:5000

---

## **🔒 Segurança**
- **Senhas**: Armazenadas como hash (bcrypt)  
- **2FA**: Códigos temporários via PyOTP  
- **Cookies**: Protegidos por chave secreta (`app.secret_key`)  
- **SQL Injection**: Prevenida com queries parametrizadas  

---

## **📧 Contato**
Desenvolvido por [Filipe Pereira Freitas] - [filipe13freitas@gmail.com]  
Contribuições são bem-vindas! 🚀