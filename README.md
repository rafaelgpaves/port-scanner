# Port Scanner

Projeto desenvolvido para a disciplina de Tecnologias Hacker, 7° semestre de Engenharia de Computação

## Como utilizar

```terminal
python main.py
```

Haverá um menu com várias possíveis ações:
1. Definir o IP do host
2. Definir o IP da rede
3. Escanear portas (TCP)
4. Escanear portas (UDP)
5. Detectar OS
6. Escanear hosts conectados a sua rede
0. Sair

Antes de fazer qualquer coisa, defina o IP do host (opção 1), podendo ser IPv4 ou IPv6 ou IP da rede e sua máscara se subnet (opção 2) que quer escanear.

Após especificar um IP para o host, selecione a opção 3 para escanear as portas TCP abertas ou a opção 4 para escanear as portas UDP abertas em um host específico

Acabando um desses dois, é possível selecionar a opção 5, que tenta detectar o sistema operacional do host utilizando *banner grabbing*. Isso depende de portas específicas estarem abertas, então um bom teste pra ver se está funcionando é testar o IP *45.33.32.156*.



Após especificar um IP da rede e máscara da subnet, selecione a opção 6 para tentar descobrir todos os IPs conectados nessa rede. Os dois modos possíveis são:
1. Busca extensiva --> basicamente tenta se conectar com portas conhecidas em todos os IPs possíveis e vê quais estão disponíveis (pode demorar bastante)
2. Envio pacote ARP --> envia um pacote "falso" pra rede e vê quem responde (CUIDADO COM ISSO, REQUER PERMISSÃO SUDO!)
