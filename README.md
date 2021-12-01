## Microservice de autenticação de usuario

### requisitos
* possuir o nodeJS e o npm instalado
* possuir um programa para testar APIs, como o Postman ou Insomnia

### Instruções

* execute o comando `npm install` para instalar as bibliotecas 

* execute o comando `npm run dev` para executar a aplicação

* A aplicação irá executar na porta 3333

* Abra o programa para testar APIs, crie uma requisição do tipo POST, na rota `/sessions` e crie um corpo no fomato Json seguindo o exemplo:
  ```
  {
    "email": "emerssoncardim@gmail.com",
    "senha": "123456",
  }
  ```
* A aplicação retornará o token, o refreshToken, as permissões, e as atribuções do usuário.

