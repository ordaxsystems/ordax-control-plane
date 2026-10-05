# Conectar o ORDAX ao ChatGPT

## Arquitetura

O ORDAX Runtime mantém o computador conectado ao Control Plane. O ChatGPT não acessa `localhost` e não precisa manter um terminal aberto.

```text
ChatGPT normal
   |
   | ORDAX for ChatGPT
   v
https://ordax-control-plane-v3.ordax-ac1ca1b50d09.workers.dev/mcp
   |
   v
ORDAX Runtime no Windows
   |
   +-- projetos
   +-- arquivos / Git
   +-- preview / processos
   +-- Computer Control
   +-- Blender / Unity
```

## Conector

A fonte do conector do ChatGPT fica em `plugins/ordax-chatgpt/`. O pacote contém somente os manifests/configuração e assets necessários para apontar o ChatGPT ao MCP remoto. O runtime real continua no dispositivo.

O nome user-facing do conector é **ORDAX for ChatGPT**. **ORDAX Studio** permanece reservado ao aplicativo first-party do ORDAX; o conector não é o Studio e não contém um Runtime próprio.

Outros providers devem seguir o mesmo padrão com conectores independentes, por exemplo `ORDAX for Grok`, reutilizando o mesmo protocolo, Control Plane, grants e handlers tipados.

## Configuração no Windows

A instalação/conexão deve deixar claro que existem duas decisões diferentes:

1. **Vincular o dispositivo à Conta ORDAX / conector remoto.** Isso determina quem pode alcançar o Runtime remotamente e quais ações/grants remotos são válidos.
2. **Escolher localmente o modo de Computer Control.** Essa escolha pertence ao dono do computador e nunca ao cliente de IA.

No ORDAX Studio, em **Acesso ao computador**, o dono escolhe:

### Bounded

Mantém controles de menor privilégio:

- filesystem limitado às pastas autorizadas, salvo quando `full_filesystem` for habilitado separadamente;
- aplicativos limitados à allowlist local;
- adequado para máquinas em que o usuário quer restringir a superfície acessível pelo conector.

### Full Access

Depois de uma confirmação local explícita, remove as allowlists ORDAX de pastas e aplicativos para todas as capabilities Computer Control suportadas.

O aviso deve explicar de forma clara que um cliente ORDAX remoto **já autorizado** poderá, conforme as capabilities disponíveis:

- ler, criar, alterar, mover e remover arquivos;
- inspecionar e controlar janelas;
- usar mouse, teclado e clipboard;
- inspecionar processos;
- capturar a tela/janela ativa;
- iniciar aplicativos suportados;
- usar outras capabilities Computer Control publicadas pelo Runtime.

Full Access não remove autenticação, grants, validação tipada, receipts/auditoria nem as permissões reais do Windows. UAC, recursos protegidos, outro usuário/sessão e operações que exigem elevação continuam sujeitos às regras do Windows.

**O ChatGPT, o conector ou qualquer outro cliente remoto não pode habilitar, ampliar ou persistir Full Access.** A alteração precisa acontecer na superfície local do ORDAX Studio ou por uma política administrada no próprio dispositivo.

O dono pode revogar Full Access a qualquer momento e voltar para Bounded; a mudança deve ter efeito imediato nas próximas ações.

## Fluxo recomendado de onboarding

```text
1. Instalar ORDAX Studio / ORDAX Runtime no Windows
2. Abrir ORDAX Studio localmente
3. Opcionalmente entrar na Conta ORDAX
4. Vincular o dispositivo ao ORDAX for ChatGPT
5. Escolher localmente:
      - Bounded
      - Full Access
6. Se Full Access:
      mostrar aviso de controle amplo do computador
      exigir confirmação local do dono
7. Usar o ORDAX for ChatGPT no cliente externo
```

A Conta ORDAX continua opcional para uso local do Studio. Ela passa a ser necessária quando o usuário quer as capacidades remotas/account-scoped correspondentes, como vínculo de dispositivo, grants remotos e acesso pelo conector.

## Produto atual

Nesta etapa não há licença nem assinatura. Conta ORDAX, quando usada, serve para autenticar/vincular o dispositivo e seus grants; ela não conecta automaticamente um provider de IA.

A UI Windows é o ORDAX Studio. A conversa acontece no cliente externo, por exemplo o ChatGPT normal, e o conector apenas disponibiliza as capabilities ORDAX autorizadas.
