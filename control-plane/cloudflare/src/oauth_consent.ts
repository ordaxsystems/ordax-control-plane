const AUTH_ORIGIN = "https://eobcxuyvhkvdmkbaihwh.supabase.co";
const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_GQUBlAVTzgNtscw9iE5vLQ_GGtdmsL5";
const SUPABASE_JS = "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm";

function jsonForScript(value: string): string {
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
}

export function oauthConsentResponse(request: Request): Response {
  const url = new URL(request.url);
  const authorizationId = url.searchParams.get("authorization_id") ?? "";
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const redirectUrl = `${url.origin}/oauth/consent?authorization_id=${encodeURIComponent(authorizationId)}`;
  const html = `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Autorizar acesso ao ORDAX</title>
<style nonce="${nonce}">
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;background:#080f19;color:#e2ebf7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px}.card{width:min(560px,100%);background:#111e30;border:1px solid #243249;border-radius:20px;padding:28px;box-shadow:0 24px 80px #0008}.eyebrow{color:#a9c9f7;font-size:12px;letter-spacing:.16em;text-transform:uppercase}h1{font-size:28px;font-weight:450;margin:10px 0 8px}p{color:#8e9db4;line-height:1.55}.panel{background:#090f1b;border:1px solid #243249;border-radius:14px;padding:16px;margin:18px 0}.row{display:flex;gap:10px;flex-wrap:wrap}input{width:100%;background:#080f19;color:#e2ebf7;border:1px solid #34445e;border-radius:10px;padding:12px;margin:6px 0}button{border:0;border-radius:10px;padding:12px 16px;font-weight:600;cursor:pointer;background:#d1e4ff;color:#172b47}.secondary{background:#1a2a40;color:#c9d8eb}.danger{background:#35212a;color:#ffc7d7}.muted{font-size:13px;color:#8e9db4}.status{white-space:pre-wrap;font-size:13px;margin-top:12px}.hidden{display:none}.details dt{font-size:12px;color:#8e9db4;margin-top:10px}.details dd{margin:3px 0 0;overflow-wrap:anywhere}code{font-size:12px;color:#a9c9f7}
</style></head><body><main class="card"><div class="eyebrow">ORDAX</div><h1>Autorizar conexão</h1><p>Autorize este cliente a acessar capabilities ORDAX no seu dispositivo. O acesso continua limitado pelos grants, pelo vínculo do dispositivo e pela política local; todas as ações permanecem auditáveis.</p>
<div id="missing" class="panel hidden">Solicitação OAuth inválida: <code>authorization_id</code> ausente.</div>
<section id="login" class="hidden"><div class="panel"><strong>Entre na sua conta ORDAX</strong><p class="muted">A senha é enviada diretamente ao Supabase Auth e nunca passa pelo Worker do ORDAX.</p><input id="email" type="email" autocomplete="email" placeholder="E-mail"><input id="password" type="password" autocomplete="current-password" placeholder="Senha"><div class="row"><button id="passwordLogin">Entrar</button><button id="magicLogin" class="secondary">Enviar link de acesso</button></div><div id="loginStatus" class="status"></div></div></section>
<section id="consent" class="hidden"><div class="panel"><div class="muted">Conectado como</div><div id="userEmail"></div><dl class="details"><dt>Cliente</dt><dd id="clientName"></dd><dt>Redirecionamento</dt><dd id="redirectUri"></dd><dt>Permissões OAuth</dt><dd id="scopes"></dd></dl></div><div class="row"><button id="approve">Autorizar</button><button id="deny" class="danger">Negar</button><button id="signOut" class="secondary">Trocar conta</button></div><div id="consentStatus" class="status"></div></section>
</main><script type="module" nonce="${nonce}">
import { createClient } from "${SUPABASE_JS}";
const authorizationId=${jsonForScript(authorizationId)};
const returnUrl=${jsonForScript(redirectUrl)};
const client=createClient(${jsonForScript(AUTH_ORIGIN)},${jsonForScript(SUPABASE_PUBLISHABLE_KEY)},{auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}});
const q=(id)=>document.getElementById(id); const show=(id,on=true)=>q(id).classList.toggle('hidden',!on); const status=(id,msg)=>q(id).textContent=msg||'';
async function load(){if(!authorizationId){show('missing');return}const {data:{session}}=await client.auth.getSession();if(!session){show('login');show('consent',false);return}show('login',false);show('consent');q('userEmail').textContent=session.user.email||session.user.id;const {data,error}=await client.auth.oauth.getAuthorizationDetails(authorizationId);if(error){status('consentStatus',error.message);return}if(!('authorization_id' in data)){location.href=data.redirect_url;return}q('clientName').textContent=data.client?.name||data.client_id||'Cliente ORDAX';q('redirectUri').textContent=data.redirect_uri||'';q('scopes').textContent=data.scope||'openid email offline_access'}
q('passwordLogin').onclick=async()=>{status('loginStatus','Entrando…');const {error}=await client.auth.signInWithPassword({email:q('email').value.trim(),password:q('password').value});if(error){status('loginStatus',error.message);return}location.reload()};
q('magicLogin').onclick=async()=>{const email=q('email').value.trim();if(!email){status('loginStatus','Informe seu e-mail.');return}status('loginStatus','Enviando link…');const {error}=await client.auth.signInWithOtp({email,options:{emailRedirectTo:returnUrl}});status('loginStatus',error?error.message:'Link enviado. Abra o e-mail neste navegador para continuar.')};
q('approve').onclick=async()=>{status('consentStatus','Autorizando…');const {data,error}=await client.auth.oauth.approveAuthorization(authorizationId);if(error){status('consentStatus',error.message);return}location.href=data.redirect_url};
q('deny').onclick=async()=>{const {data,error}=await client.auth.oauth.denyAuthorization(authorizationId);if(error){status('consentStatus',error.message);return}location.href=data.redirect_url};
q('signOut').onclick=async()=>{await client.auth.signOut();location.reload()};
await load();
</script></body></html>`;
  return new Response(html,{status:200,headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","referrer-policy":"no-referrer","x-content-type-options":"nosniff","content-security-policy":`default-src 'none'; script-src 'nonce-${nonce}' https://cdn.jsdelivr.net; style-src 'nonce-${nonce}'; connect-src ${AUTH_ORIGIN}; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`}});
}
